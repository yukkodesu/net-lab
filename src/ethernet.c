#include "ethernet.h"
#include "buf.h"
#include "config.h"
#include "net.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO
    if (buf->len < sizeof(ether_hdr_t))
      return;
    ether_hdr_t *header = (ether_hdr_t *)buf->data;
    buf_remove_header(buf, sizeof(ether_hdr_t));
    net_in(buf, swap16(header->protocol16), header->src);
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    if (buf->len < MIN_ETHER_LEN) {
      buf_add_padding(buf, MIN_ETHER_LEN - buf->len);
    }
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *header = (ether_hdr_t *)buf->data;
    memcpy(header->dst, mac, NET_MAC_LEN);
    memcpy(header->src, net_if_mac, NET_MAC_LEN);
    header->protocol16 = protocol;
    header->protocol16 = swap16(header->protocol16);
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
