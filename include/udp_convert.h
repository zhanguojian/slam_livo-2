/**
 * @file udp_convert.h
 * @author uanheng (uanheng@foxmail.com)
 * @brief
 * @version 0.1
 * @date 2026-06-03
 *
 * @copyright Copyright (c) 2026
 *
 */

#pragma once

#include <arpa/inet.h>
#include <atomic>
#include <cstdint>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <ctime>
#include <string>

#include <pcap.h>

const int POINTCLOUD_PORT = 56301;  // 点云端口
const int IMUDATA_PORT = 56401;     // IMU端口

const uint32_t LIDAR_PORT = 56300;  ///< 点云数据端口
const uint32_t IMU_PORT = 56400;    ///< IMU数据端口

const uint32_t ONE_FRAME_POINT_NUM = 20064;  ///< 一帧点云数量

#define EPOLL_MAX_EVENTS 10
#define BUFFER_SIZE 2048

#pragma pack(push, 1)

// Ethernet 头（14字节）
struct EthernetHeader {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t type;  // 0x0800 = IPv4
};

// IP 头（最小20字节）
struct IPHeader {
  uint8_t version_header_length;  // 高4位 version，低4位 header length
  uint8_t type_of_service;
  uint16_t total_length;
  uint16_t identification;
  uint16_t flags_offset;
  uint8_t time_to_live;
  uint8_t protocol;  // 17 = UDP
  uint16_t header_checksum;
  uint32_t source_address;
  uint32_t destination_address;
};

// UDP 头（标准8字节）
struct UDPHeader {
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t length;
  uint16_t checksum;
};

// IMU数据结构
struct ImuData {
  float gyro_x;  // rad/s
  float gyro_y;
  float gyro_z;
  float acc_x;  // g
  float acc_y;
  float acc_z;
};

// 点云数据结构
struct PointCloudData {
  int32_t x;  // mm
  int32_t y;
  int32_t z;
  uint8_t intensity;
  uint8_t label;
};

struct PointCloudXYZIRT {
  float x = 0.;
  float y = 0.;
  float z = 0.;
  float intensity = 0.;
  double timestamp = 0.;
};

// 点云和IMU数据的协议头
struct LivoxHeader {
  uint8_t version;         // 协议版本，一字节
  uint16_t length;         // UDP数据长度，两字节
  uint16_t time_interval;  // 采样时间，两字节 单位：0.1us
  uint16_t dot_num;        // data字段中的数量，两字节
  uint16_t udp_cnt;        // UDP包计数，两字节
  uint8_t frame_cnt;       // 点云帧计数，一字节
  uint8_t data_type;       // 数据类型，一字节, 0:IMU数据，1:单回波模式直角坐标系点云数据
  uint8_t time_type;       // 时间戳类型，一字节,
                           // 0:无同步源，时间戳为雷达开机时间，1:gPTP/PTP同步，时间戳为master时钟源时间，2:GPS时间同步
  uint8_t reserved[12];    // 保留字段，12字节
  uint32_t crc32;          // CRC32校验码，4字节
  uint64_t timestamp;      // 时间戳，8字节 单位：ns
};
#pragma pack(pop)

enum class PacketType {
  IMU = 0,    ///< IMU消息
  LIDAR,      ///< 点云消息(不满一帧)
  LIDARFULL,  ///< 点云消息(一帧点云)
  ERROR,      ///< 其他消息
};

struct Packet {
  uint8_t data[BUFFER_SIZE];       ///< 原始数据
  int32_t len;                     ///< 原始数据实际长度
  struct sockaddr_in client_addr;  ///< 源IP
  int32_t source_port;             ///< 源端口
};

/**
 * @brief 循环数组，用于接受网卡数据
 *
 */
class PacketRingBuffer {
 public:
  /**
   * @brief 获取实际写指针
   *
   * @return Packet* 实际写入内存地址
   */
  Packet* acquireWriteSlot() {
    const size_t head = head_;
    const size_t next = increment(head);

    if (next == tail_) {
      return nullptr;
    }

    return &ring_[head];
  }

  /**
   * @brief 提交写入
   *
   */
  void commitWrite() { head_ = increment(head_); }

  /**
   * @brief 获取读指针
   *
   * @return Packet*
   */
  Packet* acquireReadSlot() {
    if (tail_ == head_) {
      return nullptr;
    }

    return &ring_[tail_];
  }

  /**
   * @brief 提交读取
   *
   */
  void commitRead() { tail_ = increment(tail_); }

  /**
   * @brief 判断是否环形数组为空
   *
   * @return true 空
   * @return false 非空
   */
  bool empty() {
    if (tail_ == head_) {
      return true;
    } else {
      return false;
    }
  }

 private:
  /**
   * @brief 读写指针自加
   *
   * @param idx
   * @return size_t
   */
  size_t increment(size_t idx) { return (idx + 1) % kRingSize; }

 private:
  static constexpr size_t kRingSize = 4096;

  Packet ring_[kRingSize];

  std::atomic<size_t> head_{0};
  std::atomic<size_t> tail_{0};
};

/**
 * @brief 将文件描述符（fd）设置为“非阻塞模式
 *
 * @param fd 文件描述符
 * @return int
 */
int setNonBlocking(int fd);

/**
 * @brief 创建并绑定 UDP socket，返回 fd
 *
 * @param ip 指定IP
 * @param port 指定端口
 * @return int fd 句柄
 */
int createUdpSocket(const std::string& ip, int port);

/**
 * @brief 将 socket 添加到 epoll 实例
 *
 * @param epoll_fd epoll 句柄
 * @param sock_fd socket 句柄
 * @return int
 */
int addToEpoll(int epoll_fd, int sock_fd);

/**
 * @brief Get the Unix Timestamp object
 *
 * @return uint64_t 返回实时时钟
 */
uint64_t getUnixTimestamp();

/**
 * @brief 获取数据
 *
 * @param data 实际存储数据地址
 * @return uint64_t 时间戳
 */
uint64_t recvUdpPacketWithTimestamp(int fd, Packet* packet);
