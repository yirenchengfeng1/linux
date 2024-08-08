#!/bin/bash

# 检查输入参数数量
if [ $# -ne 1 ]; then
  echo "用法: $0 <网络接口>"
  echo "例如: $0 eth0"
  exit 1
fi

# 解析输入参数
INTERFACE=$1

# 提示用户输入IPv6地址列表
echo "请粘贴一串IPv6地址，按Ctrl+D结束输入："

# 读取输入直到结束
while IFS= read -r ipv6_address; do
  # 检查输入是否为空
  if [ -z "$ipv6_address" ]; then
    echo "发现空行，跳过。"
    continue
  fi

  # 输出输入的IPv6地址
  echo "分配IPv6地址: $ipv6_address"

  # 使用sudo将IPv6地址分配给指定的网络接口
  sudo ip -6 addr add "$ipv6_address" dev "$INTERFACE"

  # 检查分配是否成功
  if [ $? -eq 0 ]; then
    echo "成功将IPv6地址 $ipv6_address 分配给接口 $INTERFACE"
  else
    echo "分配IPv6地址 $ipv6_address 失败"
  fi
done
