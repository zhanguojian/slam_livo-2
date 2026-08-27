/* read and write utils */

#pragma once

#include <cassert>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <rclcpp/rclcpp.hpp>
#include <rclcpp/serialization.hpp>
#include <rclcpp/serialized_message.hpp>
#include <rosbag2_cpp/reader.hpp>
#include <rosbag2_storage/storage_options.hpp>
#include <rosbag2_cpp/converter_options.hpp>
#include <rosbag2_storage/serialized_bag_message.hpp>

#include <sensor_msgs/msg/imu.hpp>
#include <sensor_msgs/msg/point_cloud2.hpp>
#include <sensor_msgs/msg/image.hpp>
#include <sensor_msgs/msg/compressed_image.hpp>

#include "udp_convert.h"

using PointCloud2Msg = sensor_msgs::msg::PointCloud2;
using PointCloud2MsgPtr = PointCloud2Msg::SharedPtr;
using ImuMsg = sensor_msgs::msg::Imu;
using ImuMsgPtr = ImuMsg::SharedPtr;
using ImageMsg = sensor_msgs::msg::Image;
using ImageMsgPtr = ImageMsg::SharedPtr;

using PointCloud2Handle =
    std::function<bool(const PointCloud2Msg::ConstSharedPtr &)>;
using ImuHandle = std::function<bool(const ImuMsg::ConstSharedPtr &)>;
using ImageHandle = std::function<bool(const ImageMsg::ConstSharedPtr &)>;

/**
 * 离线数据读取统一接口。
 * 不同数据源都转换为标准 ROS2 消息，保持现有下游回调不变。
 */
class DataIO {
public:
    explicit DataIO(std::string data_file_path)
        : data_file_path_(std::move(data_file_path)) {}
    virtual ~DataIO() = default;

    virtual void go() = 0;
    virtual DataIO &addPointCloud2Handle(const std::string &topic_name,
                                         PointCloud2Handle f) = 0;
    virtual DataIO &addIMUHandle(const std::string &topic_name,
                                 ImuHandle f) = 0;
    virtual DataIO &addImageHandle(const std::string &, ImageHandle) {
        return *this;
    }

protected:
    std::string data_file_path_;
};

/**
 * ROSBAG IO
 * 指定一个包名，添加一些回调函数，就可以顺序遍历这个包。
 */
class RosbagIO : public DataIO {
public:
    explicit RosbagIO(std::string bag_filename)
        : DataIO(bag_filename)
    {
        assert(bag_filename != "");
        bag_path_ = std::string(ROOT_DIR) + "data/bag/" + bag_filename;
    }

    using MessageProcessFunction =
        std::function<bool(const rosbag2_storage::SerializedBagMessageSharedPtr m)>;

    void go() override;

    void printfBagMetaInfo()
    {
        const auto &bag_meta_info = reader_.get_metadata();
        total_message_count_ = bag_meta_info.message_count;

        std::cout << "消息总数为： " << total_message_count_ << std::endl;
        std::cout << "bag路径为:" << bag_path_ << std::endl;
        std::cout << "话题\t 话题类型\t 消息数量" << std::endl;
        for (const auto &topic : bag_meta_info.topics_with_message_count) {
            std::cout << topic.topic_metadata.name << "\t"
                      << topic.topic_metadata.type << "\t"
                      << topic.message_count << std::endl;
        }
        std::cout << "--------------------------------" << std::endl;
    }

    RosbagIO &AddHandle(const std::string &topic_name,
                        MessageProcessFunction handle)
    {
        process_func_.emplace(topic_name, std::move(handle));
        return *this;
    }

    RosbagIO &AddPointCloudHandle(const std::string &topic_name,
                                  PointCloud2Handle f)
    {
        return AddHandle(topic_name,
            [this, f](const rosbag2_storage::SerializedBagMessageSharedPtr m) -> bool {
                rclcpp::SerializedMessage serialized_msg(*m->serialized_data);
                auto msg = std::make_shared<sensor_msgs::msg::PointCloud2>();
                point_cloud_serializer_.deserialize_message(&serialized_msg, msg.get());
                if (msg == nullptr) return false;
                return f(msg);
            });
    }

    DataIO &addPointCloud2Handle(const std::string &topic_name,
                                 PointCloud2Handle f) override {
        return AddPointCloudHandle(topic_name, std::move(f));
    }

    RosbagIO &AddImuHandle(const std::string &topic_name, ImuHandle f)
    {
        return AddHandle(topic_name,
            [this, f](const rosbag2_storage::SerializedBagMessageSharedPtr m) -> bool {
                rclcpp::SerializedMessage serialized_msg(*m->serialized_data);
                auto msg = std::make_shared<sensor_msgs::msg::Imu>();
                imu_serializer_.deserialize_message(&serialized_msg, msg.get());
                if (msg == nullptr) return false;
                return f(msg);
            });
    }

    DataIO &addIMUHandle(const std::string &topic_name, ImuHandle f) override {
        return AddImuHandle(topic_name, std::move(f));
    }

    RosbagIO &AddImageHandle(const std::string &topic_name, ImageHandle f)
    {
        return AddHandle(topic_name,
            [this, f](const rosbag2_storage::SerializedBagMessageSharedPtr m) -> bool {
                rclcpp::SerializedMessage serialized_msg(*m->serialized_data);
                auto msg = std::make_shared<sensor_msgs::msg::Image>();
                image_serializer_.deserialize_message(&serialized_msg, msg.get());
                if (msg == nullptr) return false;
                return f(msg);
            });
    }

    DataIO &addImageHandle(const std::string &topic_name,
                           ImageHandle f) override {
        return AddImageHandle(topic_name, std::move(f));
    }

    void cleanProcessFunc() { process_func_.clear(); }

private:
    std::string bag_path_;
    std::string storage_id_;
    std::map<std::string, MessageProcessFunction> process_func_;

    rosbag2_cpp::Reader reader_;

    rclcpp::Serialization<sensor_msgs::msg::PointCloud2> point_cloud_serializer_;
    rclcpp::Serialization<sensor_msgs::msg::Imu> imu_serializer_;
    rclcpp::Serialization<sensor_msgs::msg::Image> image_serializer_;

    uint64_t total_message_count_ = 0llu;
    uint64_t read_message_count_ = 0llu;
};

/**
 * 海康相机连续 RAW 文件读取器。
 *
 * CSV 固定格式：
 * frame_count,sdk_frame,width,height,frame_len,pixel_type,file_offset,host_receive_ns
 *
 * 一个 .raw 文件中连续保存所有帧，通过 file_offset + frame_len 读取指定帧。
 * host_receive_ns 只用于和 PCAP Epoch Time 建立 anchor；
 * 最终 sensor_msgs/Image.header.stamp 使用 LiDAR 同步时间。
 */
class RawImageIO {
public:
    RawImageIO(const std::string &csv_path,
               const std::string &raw_path);
    ~RawImageIO();

    bool valid() const { return valid_; }

    RawImageIO &addImageHandle(ImageHandle f);

    uint64_t firstHostTimeNs() const;
    uint64_t firstSdkFrame() const;
    uint64_t lastSdkFrame() const;
    size_t frameCount() const { return frames_.size(); }

    /**
     * lidar_frame_index=0 对应 CSV 中第一张 sdk_frame。
     * 若 sdk_frame 中间跳号，则对应图像会被判定为丢失，后续不会整体错位。
     */
    bool emitFrameForLidarIndex(uint64_t lidar_frame_index,
                                uint64_t lidar_timestamp_ns);

private:
    struct FrameMeta {
        uint64_t frame_count = 0;
        uint64_t sdk_frame = 0;
        uint32_t width = 0;
        uint32_t height = 0;
        uint32_t frame_len = 0;
        uint32_t pixel_type = 0;
        uint64_t file_offset = 0;
        uint64_t host_time_ns = 0;
    };

    bool loadMetadata();
    bool validateRawFile();

    const FrameMeta *findBySdkFrame(uint64_t sdk_frame) const;
    ImageMsgPtr readFrame(const FrameMeta &meta,
                          uint64_t lidar_timestamp_ns);

    std::string csv_path_;
    std::string raw_path_;
    std::ifstream raw_stream_;

    std::vector<FrameMeta> frames_;
    bool valid_ = false;
    ImageHandle image_handle_;
};

/**
 * PCAP 点云组帧模式：
 *
 * LIDAR_ONLY:
 *   不使用图像。从 PCAP 中第一颗有效 LiDAR 点开始，每 100 ms 组一帧。
 *
 * IMAGE_SYNC:
 *   使用第一张图像的 host_receive_ns 和 PCAP Epoch Time 匹配最近的点云 UDP；
 *   取该 UDP 内部的 LiDAR timestamp 作为 frame_anchor_ns_；
 *   从该 anchor 开始每 100 ms 组一帧，并给对应图像赋相同 LiDAR 时间戳。
 */
enum class PcapFrameMode {
    LIDAR_ONLY = 0,
    IMAGE_SYNC = 1
};

class PcapIO : public DataIO {
public:
    /**
     * 单 LiDAR：
     *   PcapIO("data/mid360.pcap");
     *
     * LiDAR + Camera：
     *   PcapIO("data/mid360.pcap",
     *          "data/frames.csv",
     *          "data/camera.raw");
     */
    explicit PcapIO(const std::string &filename,
                    const std::string &raw_image_csv = "",
                    const std::string &raw_image_file = "");

    /**
     * 若已知从 STM32 触发到 MVS SDK 得到一帧的固定延迟，可设置为正数。
     * anchor 搜索时使用：target_host = first_host_receive - delay。
     * 默认 0，表示直接使用 host_receive_ns 对齐 PCAP Epoch。
     */
    PcapIO &setCameraReceiveDelayNs(int64_t delay_ns);

    PcapFrameMode frameMode() const { return frame_mode_; }
    uint64_t frameAnchorNs() const { return frame_anchor_ns_; }

    int32_t checkPacket(const pcap_pkthdr *header, const uint8_t *data);
    PacketType parsePacket(const pcap_pkthdr *header, const uint8_t *data);
    void go() override;

    DataIO &addPointCloud2Handle(const std::string &topic_name,
                                 PointCloud2Handle f) override;
    DataIO &addIMUHandle(const std::string &topic_name,
                         ImuHandle f) override;
    DataIO &addImageHandle(const std::string &topic_name,
                           ImageHandle f) override;

private:
    static constexpr uint64_t FRAME_PERIOD_NS = 100000000ULL;  // 10 Hz
    static constexpr uint64_t INVALID_FRAME_INDEX =
        std::numeric_limits<uint64_t>::max();

    void initializePointCloudMessage();
    void finalizePointCloudMessage(uint64_t frame_stamp_ns);
    void resetRuntimeState();
    void publishCompletedFrame();
    void flushLastFrame();

    bool findImageSyncAnchor();

    PcapFrameMode frame_mode_ = PcapFrameMode::LIDAR_ONLY;
    int64_t camera_receive_delay_ns_ = 0;

    // 帧时间基准。
    bool frame_anchor_ready_ = false;
    uint64_t frame_anchor_ns_ = 0;
    uint64_t anchor_pcap_host_ns_ = 0;

    // 当前正在累积的 LiDAR 帧。
    uint64_t current_frame_index_ = INVALID_FRAME_INDEX;
    uint64_t current_frame_start_ns_ = 0;

    // parsePacket() 刚刚完成的上一帧。
    bool completed_frame_pending_ = false;
    uint64_t completed_frame_index_ = INVALID_FRAME_INDEX;
    uint64_t completed_frame_stamp_ns_ = 0;

    uint16_t last_imu_cnt_ = 0;
    ImuMsgPtr imu_msg_;

    uint16_t last_lidar_cnt_ = 0;
    uint64_t last_packet_timestamp_ns_ = 0;

    std::vector<PointCloudXYZIRT> frame_points_;
    PointCloud2MsgPtr lidar_msg_;

    PointCloud2Handle point_cloud_handle_;
    ImuHandle imu_handle_;
    std::unique_ptr<RawImageIO> raw_image_io_;
};
