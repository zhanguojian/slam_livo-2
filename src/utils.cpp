// utils.cpp

#include "io_utils.h"
#include <vector>
#include <cstdint> // for int64_t
#include <limits>  // for std::numeric_limits
#include <stdexcept> // for std::out_of_range

//把一个 std::vector<int64_t> 安全地转换成 std::vector<int>，转换前检查每个数是否超出 int 的表示范围，避免直接强制转换造成数据截断或溢出。
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