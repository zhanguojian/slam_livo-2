// utils.cpp

#include "io_utils.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <opencv2/imgproc.hpp>
#include <pcap/pcap.h>
#include <sstream>
#include <stdexcept>
#include <vector>

std::vector<int> convertToIntVectorSafe(const std::vector<int64_t>& int64_vector) {
    std::vector<int> int_vector;
    int_vector.reserve(int64_vector.size());

    for (int64_t value : int64_vector) {
        if (value < std::numeric_limits<int>::min() ||
            value > std::numeric_limits<int>::max()) {
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
        std::cerr << "无法打开bag文件: " << bag_path_
                  << " 原因: " << e.what() << std::endl;
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


// ============================================================================
// 图像和pcap数据协议解析
// ============================================================================


namespace {

constexpr uint32_t PIXEL_MONO8 = 0x01080001U;
constexpr uint32_t PIXEL_BAYER_GR8 = 0x01080008U;
constexpr uint32_t PIXEL_BAYER_RG8 = 0x01080009U;
constexpr uint32_t PIXEL_BAYER_GB8 = 0x0108000AU;
constexpr uint32_t PIXEL_BAYER_BG8 = 0x0108000BU;
constexpr uint32_t PIXEL_RGB8 = 0x02180014U;
constexpr uint32_t PIXEL_BGR8 = 0x02180015U;

int bayerConversionCode(uint32_t pixel_type) {
    switch (pixel_type) {
        case PIXEL_BAYER_GR8:
            return cv::COLOR_BayerGR2BGR;
        case PIXEL_BAYER_RG8:
            return cv::COLOR_BayerRG2BGR;
        case PIXEL_BAYER_GB8:
            return cv::COLOR_BayerGB2BGR;
        case PIXEL_BAYER_BG8:
            return cv::COLOR_BayerBG2BGR;
        default:
            return -1;
    }
}

uint64_t expectedRawBytes(uint32_t pixel_type, uint32_t width, uint32_t height) 
{
    const uint64_t pixels =
        static_cast<uint64_t>(width) * static_cast<uint64_t>(height);
    switch (pixel_type) {
        case PIXEL_MONO8:
        case PIXEL_BAYER_GR8:
        case PIXEL_BAYER_RG8:
        case PIXEL_BAYER_GB8:
        case PIXEL_BAYER_BG8:
            return pixels;
        case PIXEL_RGB8:
        case PIXEL_BGR8:
            return pixels * 3ULL;
        default:
            return 0;
    }
}

//将配置文件的相对路径配置成基于项目可直接使用的路径
std::string resolveDataPath(const std::string &path)
{
    //生成一个input存储路径的变量
    const std::filesystem::path input(path);
    if (input.is_absolute()) return input.string();

    //返回绝对路径
    return (std::filesystem::path(ROOT_DIR) / input).string();
}

//从一帧 PCAP 原始网络包中，定位 UDP 头，并拿到 UDP payload 的起始地址和长度。
//pcap数据 Ethernet + IP + UDP + payload
bool getUdpPayload(const pcap_pkthdr *header, const uint8_t *data,
                   const UDPHeader *&udp, const uint8_t *&payload,
                   size_t &payload_size) 
{
    if (header == nullptr || data == nullptr ||
        header->caplen < sizeof(EthernetHeader) + sizeof(IPHeader)) {
        return false;
    }

    //这里的data是最开始的网口协议地址
    const auto *eth = reinterpret_cast<const EthernetHeader *>(data);

    //检查是不是ipv4协议
    if (ntohs(eth->type) != 0x0800) return false;   

    const auto *ip = reinterpret_cast<const IPHeader *>(
        data + sizeof(EthernetHeader));


    //定义ip协议位置，在ET网口指针位置加ip头协议大小
    const size_t ip_header_size =
        static_cast<size_t>(ip->version_header_length & 0x0F) * 4;


    //检查ip header大小
    if (ip_header_size < sizeof(IPHeader) || ip->protocol != 17) return false;

    //在ip指针上加上ip大小即udp起始指针位置
    const uint8_t *udp_data =
        reinterpret_cast<const uint8_t *>(ip) + ip_header_size;

    if (udp_data + sizeof(UDPHeader) > data + header->caplen) return false;

    //把 udp 指向 UDPHeader
    udp = reinterpret_cast<const UDPHeader *>(udp_data);

    //读取 UDP 总长度
    const size_t udp_size = ntohs(udp->length);


    //UDP 最少应该8 byte 和 UDP Header 自己声明的总长度，不能超过 PCAP 真正抓到的数据长度。
    if (udp_size < sizeof(UDPHeader) ||
        udp_data + udp_size > data + header->caplen) {
        return false;
    }

    //定位真正的 UDP Payload  payload = data（网口指针） + 14（网口header） + 20（ip header） + 8（udp header）;
    payload = udp_data + sizeof(UDPHeader);
    payload_size = udp_size - sizeof(UDPHeader);
    return true;
}


//根据源端口和目标端口判断是否是livox数据包
uint16_t getLivoxPort(const UDPHeader &udp)
{
    //ntohs 可以拆成：n = network  , to , h = host ,s = short
    const uint16_t source_port = ntohs(udp.source_port);

    if (source_port == LIDAR_PORT || source_port == IMU_PORT) {
        return source_port;
    }
    return ntohs(udp.destination_port);
}


//快速创建一个 ROS2 sensor_msgs::msg::PointField，用来描述 PointCloud2 中某一个字段的名字、字节偏移、数据类型和数量。
sensor_msgs::msg::PointField makePointField(
    const std::string &name, uint32_t offset, uint8_t datatype) 
{
    sensor_msgs::msg::PointField field;
    field.name = name;
    field.offset = offset;
    field.datatype = datatype;
    field.count = 1;
    return field;
}


//计算两个时间戳时间的绝对差值
uint64_t absDiffNs(uint64_t a, uint64_t b) {
    return a >= b ? (a - b) : (b - a);
}

/**
 * 要求 libpcap 以 ns 精度返回 header->ts,请求 libpcap 以纳秒精度返回抓包时间戳。
 * 即使原 PCAP 是 us 精度，libpcap 也会转换成 ns（末尾通常为 000）。
 */
pcap_t *openPcapNano(const std::string &path, char *error_buffer) 
{
    #ifdef PCAP_TSTAMP_PRECISION_NANO
        return pcap_open_offline_with_tstamp_precision(
            path.c_str(), PCAP_TSTAMP_PRECISION_NANO, error_buffer);
    #else
        // Ubuntu 22.04/libpcap 1.10 正常会走上面的分支。
        // 老 libpcap 没有 ns API 时只能退回默认打开。
        return pcap_open_offline(path.c_str(), error_buffer);
    #endif
}


//把 pcap_pkthdr 里的抓包时间戳统一转换成“Unix Epoch 纳秒数 uint64_t”。
uint64_t pcapEpochNs(const pcap_pkthdr *header)
{
    if (header == nullptr) return 0;

    #ifdef PCAP_TSTAMP_PRECISION_NANO
        // handle 是通过 pcap_open_offline_with_tstamp_precision(...NANO) 打开的，
        // 因此 tv_usec 字段此时实际保存的是“纳秒小数部分”。
        return static_cast<uint64_t>(header->ts.tv_sec) * 1000000000ULL +
            static_cast<uint64_t>(header->ts.tv_usec);
    #else
        // 老 libpcap 默认 timeval 为微秒。
        return static_cast<uint64_t>(header->ts.tv_sec) * 1000000000ULL +
            static_cast<uint64_t>(header->ts.tv_usec) * 1000ULL;
    #endif
}


//根据一个“主机接收到 UDP 包的时间” host_receive_ns，减去一个估计的接收延迟 delay_ns，得到一个更靠前的目标时间。
uint64_t applyReceiveDelay(uint64_t host_receive_ns, int64_t delay_ns) {
    if (delay_ns >= 0) {
        const uint64_t delay = static_cast<uint64_t>(delay_ns);
        return host_receive_ns > delay ? host_receive_ns - delay : 0;
    }

    // 允许负值用于调试：负 delay 等价于把目标时间向后移动。
    return host_receive_ns + static_cast<uint64_t>(-delay_ns);
}

}  // namespace


// ============================================================================
// RawImageIO
// ============================================================================


//这是构造函数。
RawImageIO::RawImageIO(const std::string &csv_path,
                       const std::string &raw_path)
    : csv_path_(resolveDataPath(csv_path)),
      raw_path_(resolveDataPath(raw_path)) 
{

    //当前 RawImageIO 对象csv是否处于可正常使用状态。
    valid_ = loadMetadata();
    if (!valid_) return;

    //验证连续 RAW 文件是否和 CSV 元数据匹配/是否合法。
    if (!validateRawFile()) {
        valid_ = false;
        return;
    }

    raw_stream_.open(raw_path_, std::ios::binary);
    if (!raw_stream_.is_open()) {
        std::cerr << "无法打开连续 RAW 文件: " << raw_path_ << std::endl;
        valid_ = false;
        return;
    }

    std::cout << "连续 RAW 文件打开成功: " << raw_path_ << std::endl;
    std::cout << "图像 CSV 路径: " << csv_path_ << std::endl;
}



RawImageIO::~RawImageIO() {
    if (raw_stream_.is_open()) {
        raw_stream_.close();
    }
}


//给 RawImageIO 对象设置一个图像处理回调 image_handle_，然后返回当前对象本身，方便链式调用。
RawImageIO &RawImageIO::addImageHandle(ImageHandle f)
{

    //尽量把 f 内部拥有的资源“移动”给 image_handle_，避免不必要的复制。
    image_handle_ = std::move(f);
    return *this;
}


//返回 frames_ 中第一帧图像记录的主机时间戳 host_time_ns。
uint64_t RawImageIO::firstHostTimeNs() const {
    return frames_.empty() ? 0ULL : frames_.front().host_time_ns;
}

//返回 CSV 中第一帧图像对应的相机 SDK 帧号。
uint64_t RawImageIO::firstSdkFrame() const {
    return frames_.empty() ? 0ULL : frames_.front().sdk_frame;
}

//返回当前相机数据中最后一帧的 SDK frame number。
uint64_t RawImageIO::lastSdkFrame() const {
    return frames_.empty() ? 0ULL : frames_.back().sdk_frame;
}


//加载图像的csv文件
bool RawImageIO::loadMetadata()
{
    std::ifstream input(csv_path_);
    if (!input.is_open()) {
        std::cerr << "无法打开图像元数据文件: " << csv_path_ << std::endl;
        return false;
    }

    frames_.clear();

    std::string line;
    if (!std::getline(input, line)) {
        std::cerr << "图像元数据文件为空: " << csv_path_ << std::endl;
        return false;
    }

    // 你的实际 CSV：frame_count,sdk_frame,width,height,frame_len,pixel_type,file_offset,host_receive_ns
    // 逐行读取 frame_info.csv，按逗号拆成 8 列，把每列转换成对应类型，生成一个 FrameMeta，最后存进 frames_。
    size_t line_number = 1;
    while (std::getline(input, line))
    {
        ++line_number;
        if (line.empty()) continue;

        //末尾标识
        if (!line.empty() && line.back() == '\r') line.pop_back();

        //创建字符串数组，用来保存这一行的 8 列。
        std::vector<std::string> columns;

        //把整行字符串包装成一个字符串流。
        std::stringstream stream(line);

        //用来临时保存每一列。
        std::string column;

        //按逗号分隔读取文件。
        while (std::getline(stream, column, ',')) {
            columns.push_back(column);
        }

        if (columns.size() != 8) {
            std::cerr << "图像元数据第 " << line_number
                      << " 行列数不正确，期望8列，实际 "
                      << columns.size() << "，已跳过" << std::endl;
            continue;
        }

        try {
            FrameMeta meta;
            //stoll 把字符串转成 64 位无符号整数。
            meta.frame_count = std::stoull(columns[0]);
            meta.sdk_frame = std::stoull(columns[1]);
            meta.width = static_cast<uint32_t>(std::stoul(columns[2]));
            meta.height = static_cast<uint32_t>(std::stoul(columns[3]));
            meta.frame_len = static_cast<uint32_t>(std::stoul(columns[4]));
            meta.pixel_type = static_cast<uint32_t>(
                std::stoul(columns[5], nullptr, 0));  // 支持 0x108000a
            meta.file_offset = std::stoull(columns[6]);
            meta.host_time_ns = std::stoull(columns[7]);
            frames_.push_back(meta);
        } catch (const std::exception &e) {
            std::cerr << "图像元数据第 " << line_number
                      << " 行解析失败: " << e.what() << std::endl;
        }
    }

    if (frames_.empty()) {
        std::cerr << "没有读取到有效图像元数据" << std::endl;
        return false;
    }

    // sdk_frame 是硬件/SDK帧序号，stable_sort也就是对整个 frames_ 排序,后面用它判断丢帧和建立 LiDAR 帧索引。。
    std::stable_sort(frames_.begin(), frames_.end(),
                     [](const FrameMeta &lhs, const FrameMeta &rhs) {
                         return lhs.sdk_frame < rhs.sdk_frame;
                     });

    //当前帧和上一帧对比观察是否存在丢帧
    for (size_t i = 1; i < frames_.size(); ++i) {
        const auto &prev = frames_[i - 1];
        const auto &curr = frames_[i];
        if (curr.sdk_frame != prev.sdk_frame + 1) {
            std::cerr << "相机 SDK frame 不连续: "
                      << prev.sdk_frame << " -> " << curr.sdk_frame
                      << "，中间可能存在图像丢帧" << std::endl;
        }
    }

    std::cout << "已加载图像元数据: " << frames_.size() << " 帧"
              << ", sdk_frame=" << frames_.front().sdk_frame
              << "~" << frames_.back().sdk_frame
              << std::endl;
    std::cout << "第一帧 host_receive_ns: "
              << frames_.front().host_time_ns << std::endl;

    return true;
}


//验证连续 RAW 文件是否和 CSV 元数据匹配/是否合法
bool RawImageIO::validateRawFile() 
{
    //这里创建一个错误码对象。
    std::error_code ec;

    const uint64_t actual_size =
        static_cast<uint64_t>(std::filesystem::file_size(raw_path_, ec));

    if (ec) {
        std::cerr << "无法获取 RAW 文件大小: " << raw_path_
                  << "，原因: " << ec.message() << std::endl;
        return false;
    }

    //根据 CSV 中所有帧的位置和大小，RAW 文件至少应该有多少字节。
    uint64_t required_size = 0;

    for (const auto &meta : frames_) {

        //先检查整数溢出
        if (meta.file_offset >
            std::numeric_limits<uint64_t>::max() - meta.frame_len) 
        {
            std::cerr << "RAW offset 溢出: sdk_frame="
                      << meta.sdk_frame << std::endl;
            return false;
        }

        required_size = std::max(
            required_size,
            meta.file_offset + static_cast<uint64_t>(meta.frame_len));  //计算这一帧 RAW 图像在连续 camera.raw 文件中的“结束位置”。帧在文件开始字节偏移数加字节大小
    }

    if (actual_size < required_size) {
        std::cerr << "连续 RAW 文件被截断: 实际 " << actual_size
                  << " 字节，CSV至少需要 " << required_size
                  << " 字节" << std::endl;
        return false;
    }

    std::cout << "RAW 文件大小校验通过: " << actual_size
              << " bytes，CSV需要至少 " << required_size
              << " bytes" << std::endl;
    return true;
}

const RawImageIO::FrameMeta *RawImageIO::findBySdkFrame(uint64_t sdk_frame) const
{
    //二分查找
    const auto it = std::lower_bound(    
        frames_.begin(), frames_.end(), sdk_frame,
        [](const FrameMeta &meta, uint64_t value) {
            return meta.sdk_frame < value;
        });

    if (it == frames_.end() || it->sdk_frame != sdk_frame) {
        return nullptr;
    }
    return &(*it);
}




//根据 FrameMeta 找到 RAW 文件中对应的一帧 → 读取原始像素 → 根据 pixel_type 转成 BGR 图像 → 
// 封装成 ROS2 sensor_msgs::msg::Image → 最后把图像时间戳强制赋值成对应 LiDAR 帧的时间戳。
ImageMsgPtr RawImageIO::readFrame(const FrameMeta &meta,
                                  uint64_t lidar_timestamp_ns) 
{
    //检查 RAW 文件流
    if (!raw_stream_.is_open()) {
        std::cerr << "RAW 文件流未打开" << std::endl;
        return nullptr;
    }

    //检查 width / height / frame_len
    if (meta.frame_len == 0 || meta.width == 0 || meta.height == 0) {
        std::cerr << "无效图像尺寸/长度: sdk_frame="
                  << meta.sdk_frame << std::endl;
        return nullptr;
    }

    //检查像素格式和理论字节数,计算理论 RAW 大小
    const uint64_t expected_size =
        expectedRawBytes(meta.pixel_type, meta.width, meta.height);

    if (expected_size == 0) {
        std::cerr << "暂不支持 pixel_type=0x" << std::hex << meta.pixel_type
                  << std::dec << ", sdk_frame=" << meta.sdk_frame << std::endl;
        return nullptr;
    }

    //CSV 中记录的一帧长度，是否符合 width + height + pixel_type 推导出来的理论长度。
    if (meta.frame_len != expected_size) {
        std::cerr << "frame_len 与像素格式不匹配: sdk_frame="
                  << meta.sdk_frame
                  << ", frame_len=" << meta.frame_len
                  << ", expected=" << expected_size << std::endl;
        return nullptr;
    }

    //创建raw缓冲区
    std::vector<uint8_t> raw(meta.frame_len);

    raw_stream_.clear();

    //跳到目标帧，按从开头的字节偏移数跳转，ios::beg是开头参数
    raw_stream_.seekg(static_cast<std::streamoff>(meta.file_offset),
                      std::ios::beg);

    if (!raw_stream_.good()) {
        std::cerr << "RAW seek失败: sdk_frame=" << meta.sdk_frame
                  << ", offset=" << meta.file_offset << std::endl;
        return nullptr;
    }

    //真正读取数据
    raw_stream_.read(reinterpret_cast<char *>(raw.data()),
                     static_cast<std::streamsize>(meta.frame_len));

    //gcount返回刚才实际读取了多少字节。
    if (raw_stream_.gcount() !=
        static_cast<std::streamsize>(meta.frame_len)) {
        std::cerr << "RAW读取长度错误: sdk_frame=" << meta.sdk_frame
                  << ", offset=" << meta.file_offset
                  << ", expected=" << meta.frame_len
                  << ", actual=" << raw_stream_.gcount()
                  << std::endl;
        return nullptr;
    }

    cv::Mat bgr;
    const int rows = static_cast<int>(meta.height);
    const int cols = static_cast<int>(meta.width);
    const int bayer_code = bayerConversionCode(meta.pixel_type);

    if (bayer_code >= 0) {
        const cv::Mat bayer(rows, cols, CV_8UC1, raw.data());
        cv::cvtColor(bayer, bgr, bayer_code);
    } else if (meta.pixel_type == PIXEL_MONO8) {
        const cv::Mat gray(rows, cols, CV_8UC1, raw.data());
        cv::cvtColor(gray, bgr, cv::COLOR_GRAY2BGR);
    } else if (meta.pixel_type == PIXEL_RGB8) {
        const cv::Mat rgb(rows, cols, CV_8UC3, raw.data());
        cv::cvtColor(rgb, bgr, cv::COLOR_RGB2BGR);
    } else if (meta.pixel_type == PIXEL_BGR8) {
        bgr = cv::Mat(rows, cols, CV_8UC3, raw.data()).clone();
    } else {
        std::cerr << "暂不支持 pixel_type=0x"
                  << std::hex << meta.pixel_type << std::dec
                  << ", sdk_frame=" << meta.sdk_frame << std::endl;
        return nullptr;
    }

    if (bgr.empty()) {
        std::cerr << "图像转换失败: sdk_frame=" << meta.sdk_frame << std::endl;
        return nullptr;
    }
    if (!bgr.isContinuous()) {
        bgr = bgr.clone();
    }

    auto message = std::make_shared<ImageMsg>();

    // 关键：最终图像时间不再使用 host_receive_ns，
    // 而是使用与该 LiDAR 10Hz 帧完全相同的 LiDAR 同步时间。
    message->header.stamp =
        rclcpp::Time(static_cast<int64_t>(lidar_timestamp_ns));
    message->header.frame_id = "camera";
    message->height = meta.height;
    message->width = meta.width;
    message->encoding = "bgr8";
    message->is_bigendian = false;
    message->step = meta.width * 3;

    //总像素数 * 每个像素占多少字节 ,bgr.elemSize()：
    const size_t bytes = bgr.total() * bgr.elemSize();

    //把 OpenCV 数据复制到 ROS Image,从 bgr.data 开始，把 bytes 个字节复制到 message->data。
    message->data.assign(bgr.data, bgr.data + bytes);

    return message;
}

//根据 LiDAR 的帧索引 lidar_frame_index，推算应该对应哪一个相机 sdk_frame，找到那张图，读取 RAW，赋上 LiDAR 时间戳，再通过回调 image_handle_ 送给后面的 LIVO
bool RawImageIO::emitFrameForLidarIndex(uint64_t lidar_frame_index,
                                        uint64_t lidar_timestamp_ns) 
{
    if (frames_.empty()) return false;

    //当前相机数据中第一张图像的 SDK 帧号。
    const uint64_t first_sdk = frames_.front().sdk_frame;

    //溢出保护
    if (lidar_frame_index >
        std::numeric_limits<uint64_t>::max() - first_sdk) {
        return false;
    }

    //用 LiDAR 的帧索引推算对应的相机 SDK 帧号。
    const uint64_t expected_sdk_frame = first_sdk + lidar_frame_index;
    const FrameMeta *meta = findBySdkFrame(expected_sdk_frame);

    if (meta == nullptr) {
        // 如果仍在 CSV 的 sdk 范围内，这是实际的 sdk_frame 跳号。
        if (expected_sdk_frame <= frames_.back().sdk_frame) {
            std::cerr << "缺少对应相机帧: lidar_frame="
                      << lidar_frame_index
                      << ", expected sdk_frame="
                      << expected_sdk_frame << std::endl;
        }
        return false;
    }

    const auto message = readFrame(*meta, lidar_timestamp_ns);
    if (message == nullptr) return false;

    if (!image_handle_) {
        static bool warned_no_handle = false;
        if (!warned_no_handle) {
            std::cerr << "RawImageIO 没有注册图像回调，读到的帧不会送给 LIVO"
                      << std::endl;
            warned_no_handle = true;
        }
        return false;
    }

    image_handle_(message);

    static uint64_t emitted = 0;
    ++emitted;
    if (emitted == 1 || emitted % 50 == 0) {
        std::cout << "已输出相机帧: " << emitted
                  << ", sdk_frame=" << meta->sdk_frame
                  << ", lidar_stamp_ns=" << lidar_timestamp_ns << std::endl;
    }

    return true;
}


// ============================================================================
// PcapIO
// ============================================================================

PcapIO::PcapIO(const std::string &filename,
               const std::string &raw_image_csv,
               const std::string &raw_image_file)
    : DataIO(resolveDataPath(filename)) {

    //初始化之后要输出的点云消息结构。
    initializePointCloudMessage();

    //提前预留内存
    frame_points_.reserve(ONE_FRAME_POINT_NUM);

    if (raw_image_csv.empty() && raw_image_file.empty()) {
        frame_mode_ = PcapFrameMode::LIDAR_ONLY;
        std::cout << "PcapIO 模式: LIDAR_ONLY" << std::endl;
        return;
    }

    if (raw_image_csv.empty() != raw_image_file.empty()) {
        std::cerr << "图像同步模式需要同时提供 frames.csv 和连续 .raw 文件，"
                  << "当前参数不完整，将退回 LIDAR_ONLY" << std::endl;
        frame_mode_ = PcapFrameMode::LIDAR_ONLY;
        return;
    }

    //就是动态创建一个 RawImageIO 对象。
    raw_image_io_ = std::make_unique<RawImageIO>(raw_image_csv,
                                                  raw_image_file);
    if (!raw_image_io_->valid()) {
        std::cerr << "图像数据初始化失败，将退回 LIDAR_ONLY" << std::endl;
        raw_image_io_.reset();
        frame_mode_ = PcapFrameMode::LIDAR_ONLY;
        return;
    }

    frame_mode_ = PcapFrameMode::IMAGE_SYNC;
    std::cout << "PcapIO 模式: IMAGE_SYNC" << std::endl;
}

PcapIO &PcapIO::setCameraReceiveDelayNs(int64_t delay_ns) {
    camera_receive_delay_ns_ = delay_ns;
    return *this;
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


////把当前已经缓存好的 frame_points_ 这一整帧点云，正式封装进 sensor_msgs::msg::PointCloud2，并给这帧点云设置统一的 10Hz 帧时间戳。
void PcapIO::finalizePointCloudMessage(uint64_t frame_stamp_ns) {
    if (frame_points_.empty()) return;

    // 关键：PointCloud2 header 使用固定的 10Hz 帧起点，
    // 而不是“这一帧实际收到的第一颗点”的时间。设置 ROS2 header 时间
    lidar_msg_->header.stamp =
    rclcpp::Time(static_cast<int64_t>(frame_stamp_ns));

    //frame_points_ 保存当前这一帧所有点
    lidar_msg_->width = static_cast<uint32_t>(frame_points_.size());

    //点云一整行占多少字节
    lidar_msg_->row_step = lidar_msg_->point_step * lidar_msg_->width;

    //分配足够的空间
    lidar_msg_->data.resize(lidar_msg_->row_step);

    //直接按照字节把一块内存复制到另一块内存
    std::memcpy(lidar_msg_->data.data(),
                frame_points_.data(),
                lidar_msg_->data.size());
}


//把 PcapIO 在一次 PCAP 遍历过程中产生的“运行时状态”清空，准备重新从头处理 PCAP；但在 IMAGE_SYNC 模式下，会特意保留第一遍搜索得到的同步 anchor
void PcapIO::resetRuntimeState() {
    last_imu_cnt_ = 0;
    imu_msg_.reset();
    last_lidar_cnt_ = 0;
    last_packet_timestamp_ns_ = 0;

    frame_points_.clear();
    current_frame_index_ = INVALID_FRAME_INDEX;
    current_frame_start_ns_ = 0;

    completed_frame_pending_ = false;
    completed_frame_index_ = INVALID_FRAME_INDEX;
    completed_frame_stamp_ns_ = 0;

    // IMAGE_SYNC 的 anchor 是第一遍 PCAP 搜索得到的，不能清掉。
    // LIDAR_ONLY 则需要从第二遍/正式遍历中的第一颗有效点重新建立。
    if (frame_mode_ == PcapFrameMode::LIDAR_ONLY) {
        frame_anchor_ready_ = false;
        frame_anchor_ns_ = 0;
        anchor_pcap_host_ns_ = 0;
    }
}

//检查一个 PCAP 数据包是不是“我们关心的 Livox UDP 包”，并且确认 UDP payload 至少大到能放下一个 LivoxHeader
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


//拿第一张相机的主机接收时间 host_receive_ns，在 PCAP 中寻找“主机抓包时间最接近它”的那一个 LiDAR 点云 UDP，
// 然后把这个 UDP 里的 LiDAR 设备时间 timestamp 作为后续 10Hz 组帧的 anchor
bool PcapIO::findImageSyncAnchor() {
    if (frame_mode_ != PcapFrameMode::IMAGE_SYNC || !raw_image_io_) {
        return false;
    }

    const uint64_t image_host_receive_ns = raw_image_io_->firstHostTimeNs();
    if (image_host_receive_ns == 0) {
        std::cerr << "第一张图像 host_receive_ns 无效" << std::endl;
        return false;
    }

    const uint64_t target_host_ns =
        applyReceiveDelay(image_host_receive_ns,
                          camera_receive_delay_ns_);

    //创建 libpcap 错误缓冲区
    char error_buffer[PCAP_ERRBUF_SIZE] = {};

    //打开 PCAP
    pcap_t *handle = openPcapNano(data_file_path_, error_buffer);
    if (handle == nullptr) {
        std::cerr << "寻找 anchor 时无法打开 pcap: "
                  << data_file_path_
                  << "，原因: " << error_buffer << std::endl;
        return false;
    }

    //初始化
    bool found = false;
    uint64_t best_diff_ns = std::numeric_limits<uint64_t>::max();
    uint64_t best_pcap_host_ns = 0;
    uint64_t best_lidar_ns = 0;
    uint16_t best_udp_cnt = 0;

    pcap_pkthdr *header = nullptr;
    const u_char *data = nullptr;
    int status = 0;


    //遍历整个 PCAP,header指向抓包元数据,data指向原始数据
    while ((status = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (status == 0) continue;

        const UDPHeader *udp = nullptr;
        const uint8_t *payload = nullptr;
        size_t payload_size = 0;

        
        if (!getUdpPayload(header, data, udp, payload, payload_size)) {
            continue;
        }

        if (getLivoxPort(*udp) != LIDAR_PORT ||
            payload_size < sizeof(LivoxHeader)) {
            continue;
        }

        const auto *livox_header =
            reinterpret_cast<const LivoxHeader *>(payload);

        const size_t livox_size = livox_header->length;
        if (livox_size < sizeof(LivoxHeader) ||
            livox_size > payload_size ||
            livox_header->data_type != 1 ||
            livox_header->dot_num == 0) {
            continue;
        }

        const uint64_t host_ns = pcapEpochNs(header);
        const uint64_t diff_ns = absDiffNs(host_ns, target_host_ns);

        if (!found || diff_ns < best_diff_ns) {
            found = true;
            best_diff_ns = diff_ns;
            best_pcap_host_ns = host_ns;
            best_lidar_ns = livox_header->timestamp;
            best_udp_cnt = livox_header->udp_cnt;
        }
    }

    pcap_close(handle);

    if (!found) {
        std::cerr << "PCAP 中没有找到可用于图像同步的点云 UDP"
                  << std::endl;
        return false;
    }

    frame_anchor_ns_ = best_lidar_ns;
    anchor_pcap_host_ns_ = best_pcap_host_ns;
    frame_anchor_ready_ = true;

    std::cout << "================ IMAGE_SYNC anchor ================"
              << std::endl;
    std::cout << "camera first sdk_frame     : "
              << raw_image_io_->firstSdkFrame() << std::endl;
    std::cout << "camera host_receive_ns     : "
              << image_host_receive_ns << std::endl;
    std::cout << "camera receive delay ns    : "
              << camera_receive_delay_ns_ << std::endl;
    std::cout << "anchor search target host  : "
              << target_host_ns << std::endl;
    std::cout << "matched PCAP Epoch ns      : "
              << best_pcap_host_ns << std::endl;
    std::cout << "host match abs diff ns     : "
              << best_diff_ns
              << " (" << std::fixed << std::setprecision(3)
              << static_cast<double>(best_diff_ns) / 1e6
              << " ms)" << std::defaultfloat << std::endl;
    std::cout << "matched lidar udp_cnt      : "
              << best_udp_cnt << std::endl;
    std::cout << "LiDAR frame anchor ns      : "
              << frame_anchor_ns_ << std::endl;
    std::cout << "10Hz frame period ns       : "
              << FRAME_PERIOD_NS << std::endl;
    std::cout << "==================================================="
              << std::endl;

    return true;
}

PacketType PcapIO::parsePacket(const pcap_pkthdr *header,
                               const uint8_t *data) {
    completed_frame_pending_ = false;

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

    // ------------------------------------------------------------------------
    // IMU
    // ------------------------------------------------------------------------
    if (port == IMU_PORT && livox_header->data_type == 0) {
        if (data_size < sizeof(ImuData)) return PacketType::ERROR;

        if (last_imu_cnt_ != 0 &&
            static_cast<uint16_t>(last_imu_cnt_ + 1) !=
                livox_header->udp_cnt) {
            std::cerr << "IMU UDP 包计数不连续: "
                      << last_imu_cnt_ << " -> "
                      << livox_header->udp_cnt << std::endl;
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

    // ------------------------------------------------------------------------
    // Point cloud data_type == 1
    // ------------------------------------------------------------------------
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
        std::cerr << "点云 UDP 包计数不连续: "
                  << last_lidar_cnt_ << " -> "
                  << livox_header->udp_cnt << std::endl;
    }
    last_lidar_cnt_ = livox_header->udp_cnt;

    const uint64_t base_timestamp_ns = livox_header->timestamp;
    const uint16_t dot_num = livox_header->dot_num;

    // Mid-360 协议定义：time_interval = 最后一点时间 - 第一点时间，单位0.1us。
    // 因此 N 个点只有 N-1 个间隔。
    const uint64_t total_interval_ns =
        static_cast<uint64_t>(livox_header->time_interval) * 100ULL;
    const uint64_t interval_denominator =
        dot_num >= 2 ? static_cast<uint64_t>(dot_num - 1) : 1ULL;

    for (uint16_t i = 0; i < dot_num; ++i) {
        // 用整数计算每颗点时间，避免先转 double 后再拿它做帧边界判断。
        const uint64_t point_offset_ns =
            dot_num >= 2
                ? (total_interval_ns * static_cast<uint64_t>(i) +
                   interval_denominator / 2ULL) /
                      interval_denominator
                : 0ULL;

        const uint64_t point_timestamp_ns =
            base_timestamp_ns + point_offset_ns;

        // 模式1：第一颗有效点就是第0帧起点。
        if (!frame_anchor_ready_) {
            if (frame_mode_ != PcapFrameMode::LIDAR_ONLY) {
                // IMAGE_SYNC 正常在 go() 第一遍扫描时已经得到 anchor。
                continue;
            }

            frame_anchor_ns_ = point_timestamp_ns;
            frame_anchor_ready_ = true;

            std::cout << "LIDAR_ONLY anchor = 第一颗有效点: "
                      << frame_anchor_ns_ << std::endl;
        }

        // IMAGE_SYNC：anchor 前面的点云全部丢弃，从匹配位置正式开始拼帧。
        if (point_timestamp_ns < frame_anchor_ns_) {
            continue;
        }

        const uint64_t point_frame_index =
            (point_timestamp_ns - frame_anchor_ns_) /
            FRAME_PERIOD_NS;

        if (current_frame_index_ == INVALID_FRAME_INDEX) {
            current_frame_index_ = point_frame_index;
            current_frame_start_ns_ =
                frame_anchor_ns_ + current_frame_index_ * FRAME_PERIOD_NS;
        }

        if (point_frame_index != current_frame_index_) {
            // 当前点已经进入下一时间窗，所以上一帧完成。
            if (!frame_points_.empty()) {
                completed_frame_index_ = current_frame_index_;
                completed_frame_stamp_ns_ = current_frame_start_ns_;
                finalizePointCloudMessage(completed_frame_stamp_ns_);
                completed_frame_pending_ = true;
                frame_points_.clear();
            }

            if (point_frame_index > current_frame_index_ + 1) {
                std::cerr << "LiDAR 时间出现跨帧跳跃: frame "
                          << current_frame_index_ << " -> "
                          << point_frame_index
                          << "，中间可能存在整帧数据缺失/大段丢包"
                          << std::endl;
            }

            current_frame_index_ = point_frame_index;
            current_frame_start_ns_ =
                frame_anchor_ns_ + current_frame_index_ * FRAME_PERIOD_NS;
        }

        const auto *point = reinterpret_cast<const PointCloudData *>(
            livox_data + static_cast<size_t>(i) * sizeof(PointCloudData));

        PointCloudXYZIRT output;
        output.x = static_cast<float>(point->x) * 1e-3f;
        output.y = static_cast<float>(point->y) * 1e-3f;
        output.z = static_cast<float>(point->z) * 1e-3f;
        output.intensity = static_cast<float>(point->intensity);

        // 保持你原 PointCloud2 字段定义：FLOAT64 timestamp，值仍为绝对ns。
        // 注意 double 对 1e18 量级ns不能保持1ns整数精度，但不影响上面的组帧判断；
        // 组帧完全使用 uint64_t point_timestamp_ns。
        output.timestamp = static_cast<double>(point_timestamp_ns);

        frame_points_.push_back(output);
    }

    return completed_frame_pending_
               ? PacketType::LIDARFULL
               : PacketType::LIDAR;
}

void PcapIO::publishCompletedFrame() {
    if (!completed_frame_pending_) return;

    if (point_cloud_handle_) {
        point_cloud_handle_(lidar_msg_);
    }

    if (frame_mode_ == PcapFrameMode::IMAGE_SYNC && raw_image_io_) {
        raw_image_io_->emitFrameForLidarIndex(
            completed_frame_index_,
            completed_frame_stamp_ns_);
    }

    completed_frame_pending_ = false;
}

void PcapIO::flushLastFrame() {
    if (frame_points_.empty() ||
        current_frame_index_ == INVALID_FRAME_INDEX) {
        return;
    }

    const uint64_t stamp_ns =
        frame_anchor_ns_ + current_frame_index_ * FRAME_PERIOD_NS;

    finalizePointCloudMessage(stamp_ns);

    if (point_cloud_handle_) {
        point_cloud_handle_(lidar_msg_);
    }

    if (frame_mode_ == PcapFrameMode::IMAGE_SYNC && raw_image_io_) {
        raw_image_io_->emitFrameForLidarIndex(
            current_frame_index_, stamp_ns);
    }

    frame_points_.clear();
}

void PcapIO::go() {
    std::cout << "开始读取 pcap 文件: " << data_file_path_ << std::endl;

    // ------------------------------------------------------------------------
    // IMAGE_SYNC 第一遍：只寻找 Camera host_receive <-> PCAP Epoch 的 anchor。
    // ------------------------------------------------------------------------
    if (frame_mode_ == PcapFrameMode::IMAGE_SYNC) {
        if (!findImageSyncAnchor()) {
            std::cerr << "IMAGE_SYNC anchor 查找失败，停止解析。"
                      << std::endl;
            return;
        }
    }

    // 正式解析前重置运行状态。
    resetRuntimeState();

    // resetRuntimeState() 在 IMAGE_SYNC 不会清除刚找到的 anchor。
    if (frame_mode_ == PcapFrameMode::IMAGE_SYNC &&
        !frame_anchor_ready_) {
        std::cerr << "内部错误: IMAGE_SYNC anchor 未准备好" << std::endl;
        return;
    }

    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    pcap_t *handle = openPcapNano(data_file_path_, error_buffer);
    if (handle == nullptr) {
        std::cerr << "无法打开 pcap 文件: " << data_file_path_
                  << "，原因: " << error_buffer << std::endl;
        return;
    }

    pcap_pkthdr *header = nullptr;
    const u_char *data = nullptr;
    int status = 0;

    while (rclcpp::ok() &&
           (status = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (status == 0 || checkPacket(header, data) != 0) {
            continue;
        }

        const PacketType result = parsePacket(header, data);

        if (result == PacketType::IMU && imu_msg_ && imu_handle_) {
            // 同步模式下，不把 anchor 之前的 IMU 喂给下游。
            if (frame_mode_ == PcapFrameMode::LIDAR_ONLY ||
                !frame_anchor_ready_ ||
                last_packet_timestamp_ns_ >= frame_anchor_ns_) {
                imu_handle_(imu_msg_);
            }
        }

        if (result == PacketType::LIDARFULL) {
            publishCompletedFrame();
        }
    }

    flushLastFrame();

    pcap_close(handle);

    std::cout << "pcap 文件读取完成" << std::endl;
    if (frame_anchor_ready_) {
        std::cout << "本次组帧 anchor(ns): " << frame_anchor_ns_ << std::endl;
    }
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
    if (raw_image_io_) {
        raw_image_io_->addImageHandle(std::move(f));
    }
    return *this;
}
