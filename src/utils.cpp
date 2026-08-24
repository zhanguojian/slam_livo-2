// utils.cpp

#include "io_utils.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <opencv2/imgproc.hpp>
#include <sstream>
#include <stdexcept>
#include <vector>

std::vector<int> convertToIntVectorSafe(const std::vector<int64_t>& int64_vector) {
    std::vector<int> int_vector;
    int_vector.reserve(int64_vector.size()); // 预留空间以提高效率

    for (int64_t value : int64_vector) {
        if (value < std::numeric_limits<int>::min() || value > std::numeric_limits<int>::max()) {
            throw std::out_of_range("Value is out of range for int");
        }
        int_vector.push_back(static_cast<int>(value));
    }

    return int_vector;
}


void RosbagIO::go()
{
    std::cout << "开始读取bag文件: " << bag_path_ << std::endl;
    rosbag2_storage::StorageOptions storage_options;
    storage_options.uri = bag_path_;
    storage_options.storage_id = storage_id_;
    rosbag2_cpp::ConverterOptions converter_options;
    converter_options.input_serialization_format = "cdr";
    converter_options.output_serialization_format = "cdr";
    try {
        reader_.open(storage_options, converter_options);
    } catch (const std::exception &e) {
        std::cerr << "无法打开bag文件: " << bag_path_ << " 原因: " << e.what() << std::endl;
        return;
    }
    printfBagMetaInfo();
    while (rclcpp::ok() && reader_.has_next()) {
        auto message = reader_.read_next();
        if (message == nullptr) break;
        ++read_message_count_;
        auto it = process_func_.find(message->topic_name);
        if (it != process_func_.end()) {
            it->second(message);
        }
    }
    reader_.close();
    std::cout << "读取bag文件完成" << std::endl;
    std::cout << "总消息数: " << total_message_count_ << std::endl;
    std::cout << "已读消息数: " << read_message_count_ << std::endl;
    std::cout << "--------------------------------" << std::endl;
}


namespace {

std::string resolveDataPath(const std::string &path) {
    const std::filesystem::path input(path);
    if (input.is_absolute()) return input.string();
    return (std::filesystem::path(ROOT_DIR) / input).string();
}

bool getUdpPayload(const pcap_pkthdr *header, const uint8_t *data,
                   const UDPHeader *&udp, const uint8_t *&payload,
                   size_t &payload_size) {
    if (header == nullptr || data == nullptr ||
        header->caplen < sizeof(EthernetHeader) + sizeof(IPHeader)) {
        return false;
    }

    const auto *eth = reinterpret_cast<const EthernetHeader *>(data);
    if (ntohs(eth->type) != 0x0800) return false;

    const auto *ip = reinterpret_cast<const IPHeader *>(
        data + sizeof(EthernetHeader));
    const size_t ip_header_size =
        static_cast<size_t>(ip->version_header_length & 0x0F) * 4;
    if (ip_header_size < sizeof(IPHeader) || ip->protocol != 17) return false;

    const uint8_t *udp_data =
        reinterpret_cast<const uint8_t *>(ip) + ip_header_size;
    if (udp_data + sizeof(UDPHeader) > data + header->caplen) return false;

    udp = reinterpret_cast<const UDPHeader *>(udp_data);
    const size_t udp_size = ntohs(udp->length);
    if (udp_size < sizeof(UDPHeader) ||
        udp_data + udp_size > data + header->caplen) {
        return false;
    }

    payload = udp_data + sizeof(UDPHeader);
    payload_size = udp_size - sizeof(UDPHeader);
    return true;
}

uint16_t getLivoxPort(const UDPHeader &udp) {
    const uint16_t source_port = ntohs(udp.source_port);
    if (source_port == LIDAR_PORT || source_port == IMU_PORT) {
        return source_port;
    }
    return ntohs(udp.destination_port);
}

sensor_msgs::msg::PointField makePointField(
    const std::string &name, uint32_t offset, uint8_t datatype) {
    sensor_msgs::msg::PointField field;
    field.name = name;
    field.offset = offset;
    field.datatype = datatype;
    field.count = 1;
    return field;
}

}  // namespace

RawImageIO::RawImageIO(const std::string &csv_path)
    : csv_path_(resolveDataPath(csv_path)) {
    raw_dir_ = std::filesystem::path(csv_path_).parent_path().string();
    valid_ = loadMetadata();
}

RawImageIO &RawImageIO::addImageHandle(ImageHandle f) {
    image_handle_ = std::move(f);
    return *this;
}

bool RawImageIO::loadMetadata() {
    std::ifstream input(csv_path_);
    if (!input.is_open()) {
        std::cerr << "无法打开图像元数据文件: " << csv_path_ << std::endl;
        return false;
    }

    std::string line;
    std::getline(input, line);
    size_t line_number = 1;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        std::vector<std::string> columns;
        std::stringstream stream(line);
        std::string column;
        while (std::getline(stream, column, ',')) columns.push_back(column);
        if (columns.size() != 6) {
            std::cerr << "图像元数据第 " << line_number
                      << " 行列数不正确，已跳过" << std::endl;
            continue;
        }

        try {
            FrameMeta meta;
            meta.file = columns[0];
            meta.frame_num = std::stoull(columns[1]);
            meta.width = static_cast<uint32_t>(std::stoul(columns[2]));
            meta.height = static_cast<uint32_t>(std::stoul(columns[3]));
            meta.pixel_format = columns[4];
            meta.host_time_ns = std::stoull(columns[5]);
            frames_.push_back(std::move(meta));
        } catch (const std::exception &e) {
            std::cerr << "图像元数据第 " << line_number
                      << " 行解析失败: " << e.what() << std::endl;
        }
    }

    std::stable_sort(frames_.begin(), frames_.end(),
                     [](const FrameMeta &lhs, const FrameMeta &rhs) {
                         return lhs.host_time_ns < rhs.host_time_ns;
                     });
    std::cout << "已加载 raw 图像元数据: " << frames_.size() << " 帧"
              << std::endl;
    return !frames_.empty();
}

ImageMsgPtr RawImageIO::readFrame(const FrameMeta &meta) const {
    const auto raw_path =
        (std::filesystem::path(raw_dir_) / meta.file).string();
    std::ifstream input(raw_path, std::ios::binary | std::ios::ate);
    if (!input.is_open()) {
        std::cerr << "无法打开 raw 图像: " << raw_path << std::endl;
        return nullptr;
    }

    const size_t expected_size =
        static_cast<size_t>(meta.width) * static_cast<size_t>(meta.height);
    const std::streamsize actual_size = input.tellg();
    if (actual_size != static_cast<std::streamsize>(expected_size)) {
        std::cerr << "raw 图像大小不正确: " << raw_path
                  << "，期望 " << expected_size << " 字节，实际 "
                  << actual_size << " 字节" << std::endl;
        return nullptr;
    }

    std::vector<uint8_t> raw(expected_size);
    input.seekg(0, std::ios::beg);
    if (!input.read(reinterpret_cast<char *>(raw.data()), actual_size)) {
        std::cerr << "读取 raw 图像失败: " << raw_path << std::endl;
        return nullptr;
    }

    int conversion_code = -1;
    if (meta.pixel_format == "BayerRG8" ||
        meta.pixel_format == "bayer_rggb8") {
        conversion_code = cv::COLOR_BayerRG2BGR;
    } else if (meta.pixel_format == "BayerGB8" ||
               meta.pixel_format == "bayer_gbrg8") {
        conversion_code = cv::COLOR_BayerGB2BGR;
    } else {
        std::cerr << "暂不支持的像素格式: " << meta.pixel_format << std::endl;
        return nullptr;
    }

    const cv::Mat bayer(static_cast<int>(meta.height),
                        static_cast<int>(meta.width), CV_8UC1, raw.data());
    cv::Mat bgr;
    cv::cvtColor(bayer, bgr, conversion_code);

    auto message = std::make_shared<ImageMsg>();
    message->header.stamp =
        rclcpp::Time(static_cast<int64_t>(meta.host_time_ns));
    message->header.frame_id = "camera";
    message->height = meta.height;
    message->width = meta.width;
    message->encoding = "bgr8";
    message->is_bigendian = false;
    message->step = meta.width * 3;
    message->data.assign(bgr.datastart, bgr.dataend);
    return message;
}

void RawImageIO::emitUntil(uint64_t timestamp_ns) {
    while (next_frame_index_ < frames_.size() &&
           frames_[next_frame_index_].host_time_ns <= timestamp_ns) {
        const auto message = readFrame(frames_[next_frame_index_]);
        ++next_frame_index_;
        if (message != nullptr && image_handle_) image_handle_(message);
    }
}

void RawImageIO::emitRemaining() {
    emitUntil(std::numeric_limits<uint64_t>::max());
}

PcapIO::PcapIO(const std::string &filename,
               const std::string &raw_image_csv)
    : DataIO(resolveDataPath(filename)) {
    initializePointCloudMessage();
    frame_points_.reserve(ONE_FRAME_POINT_NUM);
    if (!raw_image_csv.empty()) {
        raw_image_io_ = std::make_unique<RawImageIO>(raw_image_csv);
        if (!raw_image_io_->valid()) raw_image_io_.reset();
    }
}

void PcapIO::initializePointCloudMessage() {
    lidar_msg_ = std::make_shared<PointCloud2Msg>();
    lidar_msg_->header.frame_id = "livox_frame";
    lidar_msg_->height = 1;
    lidar_msg_->is_bigendian = false;
    lidar_msg_->is_dense = true;
    lidar_msg_->point_step = sizeof(PointCloudXYZIRT);
    lidar_msg_->fields = {
        makePointField("x", offsetof(PointCloudXYZIRT, x),
                       sensor_msgs::msg::PointField::FLOAT32),
        makePointField("y", offsetof(PointCloudXYZIRT, y),
                       sensor_msgs::msg::PointField::FLOAT32),
        makePointField("z", offsetof(PointCloudXYZIRT, z),
                       sensor_msgs::msg::PointField::FLOAT32),
        makePointField("intensity", offsetof(PointCloudXYZIRT, intensity),
                       sensor_msgs::msg::PointField::FLOAT32),
        makePointField("timestamp", offsetof(PointCloudXYZIRT, timestamp),
                       sensor_msgs::msg::PointField::FLOAT64)};
}

void PcapIO::finalizePointCloudMessage() {
    if (frame_points_.empty()) return;
    lidar_msg_->header.stamp =
        rclcpp::Time(static_cast<int64_t>(frame_points_.front().timestamp));
    lidar_msg_->width = static_cast<uint32_t>(frame_points_.size());
    lidar_msg_->row_step = lidar_msg_->point_step * lidar_msg_->width;
    lidar_msg_->data.resize(lidar_msg_->row_step);
    std::memcpy(lidar_msg_->data.data(), frame_points_.data(),
                lidar_msg_->data.size());
}

int32_t PcapIO::checkPacket(const pcap_pkthdr *header,
                            const uint8_t *data) {
    const UDPHeader *udp = nullptr;
    const uint8_t *payload = nullptr;
    size_t payload_size = 0;
    if (!getUdpPayload(header, data, udp, payload, payload_size)) return -1;
    const uint16_t port = getLivoxPort(*udp);
    if (port != IMU_PORT && port != LIDAR_PORT) return -1;
    return payload_size >= sizeof(LivoxHeader) ? 0 : -1;
}

PacketType PcapIO::parsePacket(const pcap_pkthdr *header,
                               const uint8_t *data) {
    const UDPHeader *udp = nullptr;
    const uint8_t *payload = nullptr;
    size_t payload_size = 0;
    if (!getUdpPayload(header, data, udp, payload, payload_size) ||
        payload_size < sizeof(LivoxHeader)) {
        return PacketType::ERROR;
    }

    const uint16_t port = getLivoxPort(*udp);
    const auto *livox_header =
        reinterpret_cast<const LivoxHeader *>(payload);
    const size_t livox_size = livox_header->length;
    if (livox_size < sizeof(LivoxHeader) || livox_size > payload_size) {
        std::cerr << "Livox 数据长度不合法，已丢弃数据包" << std::endl;
        return PacketType::ERROR;
    }

    last_packet_timestamp_ns_ = livox_header->timestamp;
    const uint8_t *livox_data = payload + sizeof(LivoxHeader);
    const size_t data_size = livox_size - sizeof(LivoxHeader);

    if (port == IMU_PORT && livox_header->data_type == 0) {
        if (data_size < sizeof(ImuData)) return PacketType::ERROR;
        if (last_imu_cnt_ != 0 &&
            static_cast<uint16_t>(last_imu_cnt_ + 1) !=
                livox_header->udp_cnt) {
            std::cerr << "IMU UDP 包计数不连续: " << last_imu_cnt_
                      << " -> " << livox_header->udp_cnt << std::endl;
        }
        last_imu_cnt_ = livox_header->udp_cnt;

        const auto *imu = reinterpret_cast<const ImuData *>(livox_data);
        imu_msg_ = std::make_shared<ImuMsg>();
        imu_msg_->header.stamp =
            rclcpp::Time(static_cast<int64_t>(livox_header->timestamp));
        imu_msg_->header.frame_id = "livox_frame";
        imu_msg_->angular_velocity.x = imu->gyro_x;
        imu_msg_->angular_velocity.y = imu->gyro_y;
        imu_msg_->angular_velocity.z = imu->gyro_z;
        constexpr double gravity = 9.80665;
        imu_msg_->linear_acceleration.x = imu->acc_x * gravity;
        imu_msg_->linear_acceleration.y = imu->acc_y * gravity;
        imu_msg_->linear_acceleration.z = imu->acc_z * gravity;
        return PacketType::IMU;
    }

    if (port != LIDAR_PORT || livox_header->data_type != 1) {
        return PacketType::ERROR;
    }

    const size_t max_points = data_size / sizeof(PointCloudData);
    if (livox_header->dot_num == 0 ||
        livox_header->dot_num > max_points) {
        std::cerr << "点云数量不合法: " << livox_header->dot_num
                  << "，最大点数: " << max_points << std::endl;
        return PacketType::ERROR;
    }
    if (last_lidar_cnt_ != 0 &&
        static_cast<uint16_t>(last_lidar_cnt_ + 1) !=
            livox_header->udp_cnt) {
        std::cerr << "点云 UDP 包计数不连续: " << last_lidar_cnt_
                  << " -> " << livox_header->udp_cnt << std::endl;
    }
    last_lidar_cnt_ = livox_header->udp_cnt;

    bool completed_frame = false;
    const uint64_t base_timestamp = livox_header->timestamp;
    if (!frame_points_.empty() &&
        base_timestamp >=
            static_cast<uint64_t>(frame_points_.front().timestamp) +
                100000000ULL) {
        finalizePointCloudMessage();
        frame_points_.clear();
        completed_frame = true;
    }

    const double point_interval_ns =
        static_cast<double>(livox_header->time_interval) * 100.0 /
        static_cast<double>(livox_header->dot_num);
    for (uint16_t i = 0; i < livox_header->dot_num; ++i) {
        const auto *point = reinterpret_cast<const PointCloudData *>(
            livox_data + static_cast<size_t>(i) * sizeof(PointCloudData));
        PointCloudXYZIRT output;
        output.x = static_cast<float>(point->x) * 1e-3f;
        output.y = static_cast<float>(point->y) * 1e-3f;
        output.z = static_cast<float>(point->z) * 1e-3f;
        output.intensity = static_cast<float>(point->intensity);
        output.timestamp =
            static_cast<double>(base_timestamp) + i * point_interval_ns;
        frame_points_.push_back(output);
    }

    return completed_frame ? PacketType::LIDARFULL : PacketType::LIDAR;
}

void PcapIO::go() {
    std::cout << "开始读取 pcap 文件: " << data_file_path_ << std::endl;
    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    pcap_t *handle =
        pcap_open_offline(data_file_path_.c_str(), error_buffer);
    if (handle == nullptr) {
        std::cerr << "无法打开 pcap 文件: " << data_file_path_
                  << "，原因: " << error_buffer << std::endl;
        return;
    }

    bool lidar_started = false;
    pcap_pkthdr *header = nullptr;
    const u_char *data = nullptr;
    int status = 0;
    while (rclcpp::ok() &&
           (status = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (status == 0 || checkPacket(header, data) != 0) continue;
        const PacketType result = parsePacket(header, data);
        if (result == PacketType::IMU && imu_msg_ && imu_handle_) {
            imu_handle_(imu_msg_);
        } else if (result == PacketType::LIDARFULL &&
                   point_cloud_handle_) {
            point_cloud_handle_(lidar_msg_);
            lidar_started = true;
        }

        if (lidar_started && raw_image_io_ &&
            last_packet_timestamp_ns_ != 0) {
            raw_image_io_->emitUntil(last_packet_timestamp_ns_);
        }
    }

    if (!frame_points_.empty() && point_cloud_handle_) {
        finalizePointCloudMessage();
        point_cloud_handle_(lidar_msg_);
        frame_points_.clear();
    }
    if (raw_image_io_) raw_image_io_->emitRemaining();
    pcap_close(handle);
    std::cout << "pcap 文件读取完成" << std::endl;
}

DataIO &PcapIO::addPointCloud2Handle(const std::string &,
                                     PointCloud2Handle f) {
    point_cloud_handle_ = std::move(f);
    return *this;
}

DataIO &PcapIO::addIMUHandle(const std::string &, ImuHandle f) {
    imu_handle_ = std::move(f);
    return *this;
}

DataIO &PcapIO::addImageHandle(const std::string &, ImageHandle f) {
    if (raw_image_io_) raw_image_io_->addImageHandle(std::move(f));
    return *this;
}
// void RosbagIO::go(){

//     std::cout << "开始读取bag文件: " << bag_path_ << std::endl;

//     rosbag2_storage::StorageOptions storage_options;
//     storage_options.uri = bag_path_;
//     storage_options.storage_id = "sqlite3";

//     rosbag2_cpp:ConverterOptions converter_options;
//     converter_options.input_serialization_format = "cdr";
//     converter_options.output_serialization_format = "cdr";
//     rosbag2_cpp::ConverterFactory converter_factory;
//     auto converter = converter_factory.load_converter(converter_options);
//     rosbag2_cpp::Reader reader;
//     reader.open(storage_options, converter);
    
//     printfBagMetaInfo();

//     if(!bag_reader_.is_open()){
//         std::cerr << "无法打开bag文件;文件路径错误: " << bag_path_ << std::endl;
//         return;
//     }

//     while(rclcpp::ok()){
//         auto message = bag_reader_.read_next();
//         if(message == nullptr){
//             break;
//         }
//         auto it = process_func_.find(message->topic_name);
//         if(it != process_func_.end()){
//             it->second(message);
//         }
//     }

//     bag_reader_.close();
//     std::cout << "读取bag文件完成" << std::endl;
//     std::cout << "总消息数: " << total_message_count_ << std::endl;
//     std::cout << "已读消息数: " << read_message_count_ << std::endl;
//     std::cout << "--------------------------------" << std::endl;
//     }