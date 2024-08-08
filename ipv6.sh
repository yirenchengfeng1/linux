#!/bin/bash

# 检查输入参数数量
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "用法: $0 <IPv6网络地址> <生成地址数量> [目标网络位]"
  echo "例如: $0 2001:19f0:4400:64f1::/64 10 128"
  exit 1
fi

# 解析输入参数
NETWORK=$1
COUNT=$2
TARGET_PREFIX_LENGTH=$3

echo "输入的网络地址: $NETWORK"
echo "输入的生成地址数量: $COUNT"

# 检查输入的数量是否是正整数
if ! [[ $COUNT =~ ^[0-9]+$ ]]; then
  echo "生成地址数量必须是正整数。"
  exit 1
fi

# 提取 IPv6 地址和前缀长度
IFS='/' read -r base_address prefix_length <<< "$NETWORK"

echo "解析后的基地址: $base_address"
echo "解析后的前缀长度: $prefix_length"

# 确保前缀长度在合理范围内
if [[ "$prefix_length" -lt 0 || "$prefix_length" -gt 128 ]]; then
  echo "前缀长度必须在 0 到 128 之间。"
  exit 1
fi

# 如果指定了目标网络位，确保它在合理范围内
if [[ -n "$TARGET_PREFIX_LENGTH" ]]; then
  if [[ "$TARGET_PREFIX_LENGTH" -lt "$prefix_length" || "$TARGET_PREFIX_LENGTH" -gt 128 ]]; then
    echo "目标网络位必须在当前前缀长度和 128 之间。"
    exit 1
  fi
else
  TARGET_PREFIX_LENGTH=$prefix_length  # 如果未指定，则保持与输入前缀一致
fi

echo "目标网络位长度: $TARGET_PREFIX_LENGTH"

# 将 IPv6 地址转换为十六进制数组
ipv6_to_hex_array() {
  local ip="$1"
  local hex_array=()
  IFS=':' read -ra parts <<< "$ip"

  # 将缺省部分补充完整
  local missing_parts=$((8 - ${#parts[@]}))
  for ((i=0; i<missing_parts; i++)); do
    parts+=("")
  done

  for part in "${parts[@]}"; do
    if [ -z "$part" ]; then
      hex_array+=("0000")
    else
      hex_array+=($(printf "%04x" "0x$part"))
    fi
  done

  echo "${hex_array[@]}"
}

# 将十六进制数组转换为 IPv6 地址
hex_array_to_ipv6() {
  local hex_array=("$@")
  local ipv6=""
  for part in "${hex_array[@]}"; do
    ipv6+="${part}:"
  done
  echo "${ipv6%:}"
}

# 随机生成一个完整的 IPv6 地址
generate_random_ipv6() {
  local base_hex_array=("$@")

  # 从prefix_length开始随机生成
  local start_index=$((prefix_length / 16))
  local end_index=$((TARGET_PREFIX_LENGTH / 16))
  for ((i=start_index; i<end_index; i++)); do
    # 生成随机的四位十六进制数
    local random_value=$(printf "%04x" $((RANDOM % 65536)))
    base_hex_array[i]=$random_value
  done

  echo "${base_hex_array[@]}"
}

# 将基地址转换为十六进制数组
base_hex_array=($(ipv6_to_hex_array "$base_address"))

# 生成指定数量的随机IPv6地址
generate_ipv6_addresses() {
  local base_hex_array=("$@")
  local count=$COUNT

  for ((i=0; i<count; i++)); do
    # 生成新的随机地址
    local new_hex_array=($(generate_random_ipv6 "${base_hex_array[@]}"))
    local new_address=$(hex_array_to_ipv6 "${new_hex_array[@]}")
    echo "$new_address/$TARGET_PREFIX_LENGTH"
  done
}

# 调用函数生成 IPv6 地址
generate_ipv6_addresses "${base_hex_array[@]}"
