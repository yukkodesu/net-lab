#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "buf.h"
#include "config.h"
#include "map.h"
#include "net.h"
#include "arp.h"
#include "ethernet.h"
#include "utils.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    buf_t *buf = malloc(sizeof(buf_t));
    buf_init(buf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = buf->data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    pkt->opcode16 = swap16(ARP_REQUEST);
    buf_add_padding(buf, MIN_ETHER_LEN - buf->len);
    ethernet_out(buf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_t *buf = malloc(sizeof(buf_t));
    buf_init(buf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = buf->data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_init_pkt));
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);
    pkt->opcode16 = swap16(ARP_REPLY);
    buf_add_padding(buf, MIN_ETHER_LEN - buf->len);
    ethernet_out(buf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if (buf->len < ARP_HEAD_LENGTH) {
      return;
    }
    arp_pkt_t *pkt = buf->data;
    if (memcmp(pkt, &arp_init_pkt, 6) != 0) {
      return;
    }
    uint8_t my_ip[] = NET_IF_IP;
    if (pkt->opcode16 == swap16(ARP_REQUEST) &&
        memcmp(pkt->target_ip, my_ip, NET_IP_LEN) == 0) {
      arp_resp(pkt->sender_ip, src_mac);
    }
    map_set(&arp_table, pkt->sender_ip, src_mac);
    buf_t *previous_buf = map_get(&arp_buf, pkt->sender_ip);
    if (previous_buf != NULL) {
      map_delete(&arp_buf, pkt->sender_ip);
      ethernet_out(previous_buf, src_mac, NET_PROTOCOL_IP);
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    uint8_t *mac = map_get(&arp_table, ip);
    if (mac != NULL) {
      ethernet_out(buf, mac, NET_PROTOCOL_IP);
      return;
    }
    buf_t *previous_buf = map_get(&arp_buf, ip);
    if (previous_buf != NULL) {
      return;
    }
    map_set(&arp_buf, ip, buf);
    arp_req(ip);
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}