/* read and write utils */

#pragma once

#include <cassert>
#include <cstdint>
#include <functional>
#include <iostream>
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
 * 指定一个包名，添加一些回调函数，就可以顺序遍历这个包
 */
class RosbagIO : public DataIO {
public:
    // 传入 rosbag2 的目录路径（包含 metadata.yaml 的文件夹），或完整 uri
    explicit RosbagIO(std::string bag_filename)
        : DataIO(bag_filename)
    {
        assert(bag_filename != "");
        // rosbag2 录制的是“目录”，open 时传目录即可
        bag_path_ = std::string(ROOT_DIR) + "data/bag/" + bag_filename;
    }

    // 通用回调
    using MessageProcessFunction =
        std::function<bool(const rosbag2_storage::SerializedBagMessageSharedPtr m)>;

    // 运行主函数
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

    // 通用处理函数
    RosbagIO &AddHandle(const std::string &topic_name, MessageProcessFunction handle)
    {
        process_func_.emplace(topic_name, std::move(handle));
        return *this;
    }

    // 点云 handle
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

    // imu handle
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

    // image handle
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
 * 海康相机 raw 图像读取器。
 * CSV 格式：file,frame_num,width,height,pixel_format,host_time_ns
 */
class RawImageIO {
public:
    explicit RawImageIO(const std::string &csv_path);

    bool valid() const { return valid_; }
    RawImageIO &addImageHandle(ImageHandle f);
    void emitUntil(uint64_t timestamp_ns);
    void emitRemaining();

private:
    struct FrameMeta {
        std::string file;
        uint64_t frame_num = 0;
        uint32_t width = 0;
        uint32_t height = 0;
        std::string pixel_format;
        uint64_t host_time_ns = 0;
    };

    bool loadMetadata();
    ImageMsgPtr readFrame(const FrameMeta &meta) const;

    std::string csv_path_;
    std::string raw_dir_;
    std::vector<FrameMeta> frames_;
    size_t next_frame_index_ = 0;
    bool valid_ = false;
    ImageHandle image_handle_;
};

class PcapIO : public DataIO {
public:
    explicit PcapIO(const std::string &filename,
                    const std::string &raw_image_csv = "");

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
    void initializePointCloudMessage();
    void finalizePointCloudMessage();

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