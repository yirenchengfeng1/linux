#!/bin/bash

# 检查输入参数数量
if [ $# -ne 1 ]; then
  echo "用法: $0 <网络接口>"
  echo "例如: $0 eth0"
  exit 1
fi

# 解析输入参数
INTERFACE=$1

# 提示用户输入一个IPv6地址
read -p "请输入您要分配的IPv6地址（带前缀长度，例如 /64）： " ipv6_address

# 检查输入是否为空
if [ -z "$ipv6_address" ]; then
  echo "没有输入任何IPv6地址。"
  exit 1
fi

# 输出输入的IPv6地址
echo "输入的IPv6地址: $ipv6_address"

# 使用sudo将IPv6地址分配给指定的网络接口
sudo ip -6 addr add "$ipv6_address" dev "$INTERFACE"

# 检查分配是否成功
if [ $? -eq 0 ]; then
  echo "成功将IPv6地址 $ipv6_address 分配给接口 $INTERFACE，重启将会失效"
else
  echo "分配IPv6地址失败"
  exit 1
fi
