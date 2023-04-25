#include "ip.h"
#include "arp.h"
#include "buf.h"
#include "config.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"
#include "utils.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
  // TO-DO
  if (buf->len < sizeof(ip_hdr_t))
    return;
  ip_hdr_t *hdr = buf->data;
  uint16_t total_len = swap16(hdr->total_len16);
  if (hdr->version != IP_VERSION_4 && total_len > buf->len)
    return;
  ip_hdr_t *hdr_bak = malloc(sizeof(ip_hdr_t));
  memcpy(hdr_bak, hdr, sizeof(ip_hdr_t));
  hdr->hdr_checksum16 = 0;
  uint16_t checksum = checksum16(hdr, (hdr->hdr_len) * IP_HDR_LEN_PER_BYTE);
  if (checksum != hdr_bak->hdr_checksum16)
    return;
  hdr->hdr_checksum16 = checksum;
  free(hdr_bak);
  if (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0)
    return;
  if (buf->len > total_len) {
    buf_remove_padding(buf, buf->len - total_len);
  }
  buf_remove_header(buf, sizeof(ip_hdr_t));
  if (net_in(buf, hdr->protocol, hdr->src_ip) == -1) {
    icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    return;
  }
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id,
                     uint16_t offset, int mf) {
  // TO-DO
  buf_add_header(buf, sizeof(ip_hdr_t));
  ip_hdr_t *hdr = buf->data;
  hdr->version = IP_VERSION_4;
  hdr->hdr_len = sizeof(ip_hdr_t) >> 2;
  hdr->tos = 0;
  hdr->total_len16 = swap16(buf->len);
  hdr->ttl = 64;
  memcpy(hdr->dst_ip, ip, NET_IP_LEN);
  memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
  hdr->protocol = protocol;
  hdr->id16 = swap16(id);
  hdr->flags_fragment16 = swap16((mf & 1) << 13 | (offset & 0x1fff));
  hdr->hdr_checksum16 = 0;
  hdr->hdr_checksum16 = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));
  arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
  // TO-DO
  // if (buf->len <= ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)) {
  //   ip_fragment_out(buf, ip, protocol, 0, 0, 0);
  //   return;
  // }
  int sended = 0;
  uint8_t *p = buf->data;
  int max_package_size = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
  while (buf->len - sended > max_package_size) {
    buf_init(&txbuf, max_package_size);
    memcpy(txbuf.data, p, max_package_size);
    ip_fragment_out(&txbuf, ip, protocol, id, sended >> 3, 1);
    sended += max_package_size;
    p += max_package_size;
  }
  if (buf->len - sended != 0) {
    int size = buf->len - sended;
    buf_init(&txbuf, size);
    memcpy(txbuf.data, p, size);
    ip_fragment_out(&txbuf, ip, protocol, id, sended >> 3, 0);
  }
  id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() { net_add_protocol(NET_PROTOCOL_IP, ip_in); }