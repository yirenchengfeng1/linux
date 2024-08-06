#!/bin/bash
# REALITY一键安装脚本
# Author: YouTube频道<https://www.youtube.com/@aifenxiangdexiaoqie>

RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'


colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}

checkSystem() {
    result=$(id | awk '{print $1}')
    if [[ $result != "uid=0(root)" ]]; then
        colorEcho $RED " 请以root身份执行该脚本"
        exit 1
    fi

    res=`which yum 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        res=`which apt 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            colorEcho $RED " 不受支持的Linux系统"
            exit 1
        fi
        PMT="apt"
        CMD_INSTALL="apt install -y "
        CMD_REMOVE="apt remove -y "
        CMD_UPGRADE="apt update; apt upgrade -y; apt autoremove -y"
    else
        PMT="yum"
        CMD_INSTALL="yum install -y "
        CMD_REMOVE="yum remove -y "
        CMD_UPGRADE="yum update -y"
    fi
    res=`which systemctl 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        colorEcho $RED " 系统版本过低，请升级到最新版本"
        exit 1
    fi
}



status_singbox() {
    export PATH=/usr/local/bin:$PATH
    cmd="$(command -v /root/sing-box)"
    if [[ "$cmd" = "" ]]; then
        echo 0
        return
    fi
    if [[ ! -f /root/reality.json ]]; then
        echo 1
        return
    fi
	
	port=`grep -o '"listen_port": [0-9]*' /root/reality.json | awk '{print $2}'`
	if [[ -n "$port" ]]; then
        res=`ss -ntlp| grep ${port} | grep sing-box`
        if [[ -z "$res" ]]; then
            echo 2
        else
            echo 3
        fi
	else
	    echo 2
	fi
	
}

statusText_singbox() {
    res=`status_singbox`
    case $res in
        2)
            echo -e ${GREEN}已安装singbox${PLAIN} ${RED}未运行${PLAIN}
            ;;
        3)
            echo -e ${GREEN}已安装singbox${PLAIN} ${GREEN}正在运行${PLAIN}
            ;;
        *)
            echo -e ${RED}未安装singbox${PLAIN}
            ;;
    esac
}

preinstall() {
    $PMT clean all
    [[ "$PMT" = "apt" ]] && $PMT update
    echo ""
    echo "安装必要软件，请等待..."
    if [[ "$PMT" = "apt" ]]; then
		res=`which ufw 2>/dev/null`
        [[ "$?" != "0" ]] && $CMD_INSTALL ufw
	fi	
    res=`which curl 2>/dev/null`
    [[ "$?" != "0" ]] && $CMD_INSTALL curl
    res=`which openssl 2>/dev/null`
    [[ "$?" != "0" ]] && $CMD_INSTALL openssl
	res=`which qrencode 2>/dev/null`
    [[ "$?" != "0" ]] && $CMD_INSTALL qrencode
	res=`which jq 2>/dev/null`
    [[ "$?" != "0" ]] && $CMD_INSTALL jq

    if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
        setenforce 0
    fi
}

# 定义函数，返回随机选择的域名
random_website() {
    domains=(
        "one-piece.com"
        "www.lovelive-anime.jp"
        "www.swift.com"
        "academy.nvidia.com"
        "www.cisco.com"
        "www.samsung.com"
        "www.amd.com"
        "www.apple.com"
        "music.apple.com"
        "www.amazon.com"		
        "www.fandom.com"
        "tidal.com"
        "zoro.to"
        "www.pixiv.co.jp"
        "mxj.myanimelist.net"
        "mora.jp"
        "www.j-wave.co.jp"
        "www.dmm.com"
        "booth.pm"
        "www.ivi.tv"
        "www.leercapitulo.com"
        "www.sky.com"
        "itunes.apple.com"
        "download-installer.cdn.mozilla.net"	
    )

    total_domains=${#domains[@]}
    random_index=$((RANDOM % total_domains))
    
    # 输出选择的域名
    echo "${domains[random_index]}"
}

# 安装 singbox内核
installSingbox() {
	echo ""
	echo "请选择安装版本:"
	colorEcho $BLUE "1. 稳定版"
	colorEcho $BLUE "2. 测试版"
	echo ""
	read -p "请输入你的选择 (1-2, default: 1): " version_choice
	echo ""
	version_choice=${version_choice:-1}

	# Set the tag based on user choice
	if [ "$version_choice" -eq 2 ]; then
	echo "正在安装测试版..."
		latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name')
	else
	echo "正在安装稳定版..."
		latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')
	fi

	# No need to fetch the latest version tag again, it's already set based on user choice
	latest_version=${latest_version_tag#v}  # Remove 'v' prefix from version number
	#echo "最新版本: $latest_version"
	#echo ""

	# Detect server architecture
	arch=$(uname -m)
	#echo "Architecture: $arch"
	#echo ""

	# Map architecture names
	case ${arch} in
		x86_64)
			arch="amd64"
			;;
		aarch64)
			arch="arm64"
			;;
		armv7l)
			arch="armv7"
			;;
	esac
	
    # Prepare package names
    package_name="sing-box-${latest_version}-linux-${arch}"

    # Prepare download URL
    url="https://github.com/SagerNet/sing-box/releases/download/${latest_version_tag}/${package_name}.tar.gz"

    # Download the latest release package (.tar.gz) from GitHub
    curl -sLo "/root/${package_name}.tar.gz" "$url"

    # Extract the package and move the binary to /root
    tar -xzf "/root/${package_name}.tar.gz" -C /root
    mv "/root/${package_name}/sing-box" /root/

    # Cleanup the package
    rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"

    # Set the permissions
    chown root:root /root/sing-box
    chmod +x /root/sing-box
	mkdir -p /root/singbox
	touch /root/reality.json
    colorEcho $BLUE "已安装最新$latest_version版本"
	sleep 5
}

install_singbox() {

    # Generate uuid
	echo ""
    echo "正在生成UUID..."
	/root/sing-box generate uuid > /root/singbox/uuid
    uuid=`cat /root/singbox/uuid`
    colorEcho $BLUE "UUID：$uuid"
	
	# Generate nodename
	echo ""
	read -p "请输入您的节点名称，如果留空将保持默认：" node_name
	[[ -z "$node_name" ]] && node_name="Reality(by小企鹅)"
    colorEcho $BLUE "节点名称：$node_name"
	echo "$node_name" > /root/singbox/name
	echo ""

	# Generate key pair
    echo "正在生成私钥和公钥，请妥善保管好..."
	key_pair=$(/root/sing-box generate reality-keypair)

	# Extract private key and public key
	private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
	public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
    colorEcho $BLUE "$private_key"
    colorEcho $BLUE "$public_key"
	
	# Save the public key in a file using base64 encoding
	echo "$public_key" | base64 > /root/public.key.b64
	
    # Retrieve the server IP address
	echo ""
	# 尝试获取 IP 地址
    LOCAL_IPv4=$(curl -s -4 https://api.ipify.org)
    LOCAL_IPv6=$(curl -s -6 https://api64.ipify.org)
    # 检查 IPv是否存在且合法
    if [[ -n "$LOCAL_IPv4" && "$LOCAL_IPv4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        # 检查 IPv6 是否存在且合法
        if [[ -n "$LOCAL_IPv6" && "$LOCAL_IPv6" =~ ^([0-9a-fA-F:]+)$ ]]; then
            colorEcho $YELLOW "本机 IPv4 地址："$LOCAL_IPv4""		    
            colorEcho $YELLOW "本机 IPv6 地址："$LOCAL_IPv6""
	        read -p "请确定你的节点ip，默认ipv4（0：ipv4；1：ipv6）:" USER_IP
	        if [[ $USER_IP == 1 ]]; then
                server_ip=$LOCAL_IPv6
	            colorEcho $BLUE "节点ip："$server_ip""				
            else
                server_ip=$LOCAL_IPv4
	            colorEcho $BLUE "节点ip："$server_ip""						
            fi								
        else
		    colorEcho $YELLOW "本机仅有 IPv4 地址："$LOCAL_IPv4""		
		    server_ip=$LOCAL_IPv4
            colorEcho $BLUE "节点ip："$server_ip""
        fi
    else
	    if [[ -n "$LOCAL_IPv6" && "$LOCAL_IPv6" =~ ^([0-9a-fA-F:]+)$ ]]; then
	        colorEcho $YELLOW "本机仅有 IPv6 地址："$LOCAL_IPv6""		
		    server_ip=$LOCAL_IPv6
            colorEcho $BLUE "节点ip："$server_ip""
		else
            colorEcho $RED "未能获取到有效的公网 IP 地址。"		
		fi
    fi
    # 将 IP 地址写入文件
    echo "$server_ip" > /root/singbox/ip


	# Ask for listen port
	echo ""
    while true
    do
        read -p "请设置singbox的端口号[1025-65535]，不输入则随机生成:" listen_port
        [[ -z "$listen_port" ]] && listen_port=`shuf -i1025-65000 -n1`
        if [[ "${listen_port:0:1}" = "0" ]]; then
            echo -e "${RED}端口不能以0开头${PLAIN}"
            exit 1
        fi
        expr $listen_port + 0 &>/dev/null
        if [[ $? -eq 0 ]]; then
            if [[ $listen_port -ge 1025 ]] && [[ $listen_port -le 65535 ]]; then
	            echo "$listen_port" > /root/singbox/port				
                colorEcho $BLUE "端口号：$listen_port"
                break
            else
                colorEcho $RED "输入错误，端口号为1025-65535的数字"
            fi
        else
            colorEcho $RED "输入错误，端口号为1025-65535的数字"
        fi
    done
	
	# open port 
	echo ""
	echo "正在开启$listen_port端口..."	
    if [ -x "$(command -v firewall-cmd)" ]; then							  
        firewall-cmd --permanent --add-port=${listen_port}/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=${listen_port}/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
		colorEcho $YELLOW "$listen_port端口已成功开启"
	elif [ -x "$(command -v ufw)" ]; then								  
        ufw allow ${listen_port}/tcp > /dev/null 2>&1
        ufw allow ${listen_port}/udp > /dev/null 2>&1
	    ufw reload > /dev/null 2>&1
		colorEcho $YELLOW "$listen_port端口已成功开启"
    else
	    colorEcho $RED "无法配置防火墙规则。请手动配置以确保新singbox端口可用!"
    fi
	
	# Ask for server name (sni)
    echo ""
    read -p "请输入您的 dest 地址并确保该域名在国内的连通性（例如：www.amazon.com），如果留空将随机生成：" DEST
	if [[ -z "$DEST" ]]; then
		# 反复随机选择域名，直到符合条件
		while true; do
			# 调用函数获取随机域名
			domain=$(random_website)
			# 使用 OpenSSL 检查域名的 TLS 信息
			check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
			# 如果 check_num 等于 3，表示符合条件，跳出循环
			if [ "$check_num" -eq 3 ]; then
				DEST="$domain"
				break
			fi
		done
		
	    echo $DEST > /root/singbox/dest		
		echo $DEST > /root/singbox/servername
	    server_name=`cat /root/singbox/servername`
		colorEcho $BLUE "选中的符合条件的网站是： $server_name"	
	else
		echo "正在检查 \"${DEST}\" 是否支持 TLSv1.3与h2"
		# 检查是否支持 TLSv1.3与h2
        check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${DEST}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
		if [[ ${check_num} -eq 3 ]]; then
			echo $DEST > /root/singbox/dest		
		    echo $DEST > /root/singbox/servername
	        server_name=`cat /root/singbox/servername`
			colorEcho $YELLOW "目标网址：\"${DEST}\" 支持 TLSv1.3 与 h2"

		else
			colorEcho $YELLOW "目标网址：\"${DEST}\" 不支持 TLSv1.3 与 h2，将在默认域名组中随机挑选域名"
			# 反复随机选择域名，直到符合条件
			while true; do
				# 调用函数获取随机域名
				domain=$(random_website)
				# 使用 OpenSSL 检查域名的 TLS 信息
				check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
				# 如果 check_num 等于 3，表示符合条件，跳出循环
				if [ "$check_num" -eq 3 ]; then
					DEST="$domain"
					break
				fi
			done
			
			echo $DEST > /root/singbox/dest		
			echo $DEST > /root/singbox/servername
			server_name=`cat /root/singbox/servername`
			colorEcho $BLUE "选中的符合条件的网站是： $server_name"				

		fi	   
	fi	

	# Generate short_id
	echo ""
    echo "正在生成shortID..." 
    /root/sing-box generate rand --hex 8 > /root/singbox/sid
    short_id=`cat /root/singbox/sid`
    colorEcho $BLUE  "shortID：$short_id"
	echo ""
	

# Create reality.json using jq
jq -n --arg listen_port "$listen_port" --arg server_name "$server_name" --arg private_key "$private_key" --arg short_id "$short_id" --arg uuid "$uuid" --arg server_ip "$server_ip" '{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": ($listen_port | tonumber),
      "sniff": true,
      "sniff_override_destination": true,
      "domain_strategy": "ipv4_only",
      "users": [
        {
          "uuid": $uuid,
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": $server_name,
          "reality": {
          "enabled": true,
          "handshake": {
            "server": $server_name,
            "server_port": 443
          },
          "private_key": $private_key,
          "short_id": [$short_id]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}' > /root/reality.json

# Create sing-box.service
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/root/sing-box run -c /root/reality.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

# Check configuration and start the service
if /root/sing-box check -c /root/reality.json; then
    echo "所有配置完成，正在启动singbox程序..."
    systemctl daemon-reload
    systemctl enable sing-box > /dev/null 2>&1
    systemctl start sing-box
    systemctl restart sing-box

# Generate the link

	if [[ "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        server_link="vless://$uuid@$server_ip:$listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#$node_name"
	elif [[ "$server_ip" =~ ^([0-9a-fA-F:]+)$ ]]; then 
        server_link="vless://$uuid@[$server_ip]:$listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#$node_name"
	else
	    colorEcho $RED "没有获取到有效ip！"
	fi
	
    # Print the server details
    echo ""
    colorEcho $BLUE "reality节点配置信息如下："
    colorEcho $YELLOW "Server IP: ${PLAIN}$server_ip"
    colorEcho $YELLOW "Listen Port: ${PLAIN}$listen_port"
    colorEcho $YELLOW "Server Name: ${PLAIN}$server_name"
    colorEcho $YELLOW "Public Key: ${PLAIN}$public_key"
    colorEcho $YELLOW "Short ID: ${PLAIN}$short_id"
    colorEcho $YELLOW "UUID: ${PLAIN}$uuid"
    echo ""
    echo ""
    colorEcho $BLUE "${BLUE}reality订阅链接${PLAIN}：${server_link}"	
	echo ""
    echo ""
	colorEcho $YELLOW "reality节点二维码（可直接扫码导入到v2rayN、shadowrocket等客户端...）："
	qrencode -o - -t utf8 -s 1 ${server_link}
    #qrencode -o /tmp/singbox_reality.png -s 2 ${server_link}
	#colorEcho $YELLOW "订阅二维码已保存在/tmp/singbox_reality.png，请下载使用..."	
    echo ""
    echo ""
else
    colorEcho $RED "配置错误."
fi
}

reinstallSingbox() {
    colorEcho $BLUE "正在重新安装..."
	# Uninstall previous installation
	systemctl stop sing-box
	systemctl disable sing-box > /dev/null 2>&1
	rm /etc/systemd/system/sing-box.service
	rm /root/reality.json
	rm /root/sing-box
	rm /root/public.key.b64
	rm -rf /root/singbox

}

Switch_singboxcore() {
	echo ""
	echo "更新singbox内核..."
	# Extract the current version
	current_version_tag=$(/root/sing-box version | grep 'sing-box version' | awk '{print $3}')

	# Fetch the latest stable and alpha version tags
	latest_stable_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')
	latest_alpha_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name')

	# Determine current version type (stable or alpha)
    if [[ $current_version_tag == *"-alpha"* ]]; then
	    singbox_version="测试版"
	else
	    singbox_version="稳定版"
	fi
	colorEcho $YELLOW "当前已安装$singbox_version：$current_version_tag"
	colorEcho $BLUE "当前最新稳定版：$latest_stable_version"	
	colorEcho $BLUE "当前最新测试版：$latest_alpha_version"
	
	echo ""
	echo 0. 保持不变	
	echo 1. 升级最新稳定版
	echo 2. 升级最新测试版
	read -p "请输入你的选择（0-2）:" USER_CHOICE
	case $USER_CHOICE in 
		1)
			new_version_tag=$latest_stable_version
			singbox_version="稳定版"
			;;
		2)
			new_version_tag=$latest_alpha_version	
			singbox_version="测试版"			
			;;
			
		0)
			colorEcho $BLUE "保持不变"
			exit 0
			;;				
		*)
			colorEcho $RED "无效选择"
			exit 1
			;;
    esac
	
	# Stop the service before updating
    res=`status_singbox`
    case $res in
        3)
	        systemctl stop sing-box 
            ;;
    esac
	

	# Download and replace the binary
	arch=$(uname -m)
	case $arch in
		x86_64) arch="amd64" ;;
		aarch64) arch="arm64" ;;
		armv7l) arch="armv7" ;;
	esac

	package_name="sing-box-${new_version_tag#v}-linux-${arch}"
	url="https://github.com/SagerNet/sing-box/releases/download/${new_version_tag}/${package_name}.tar.gz"

	curl -sLo "/root/${package_name}.tar.gz" "$url"
	tar -xzf "/root/${package_name}.tar.gz" -C /root
	mv "/root/${package_name}/sing-box" /root/sing-box

	# Cleanup the package
	rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"

	# Set the permissions
	chown root:root /root/sing-box
	chmod +x /root/sing-box

	# Restart the service with the new binary
	systemctl daemon-reload
    case $res in
        2)
	        systemctl start sing-box 
            ;;
    esac

	colorEcho $YELLOW "已更新到$singbox_version：$new_version_tag"
	echo ""
	sleep 5

}


UninstallSingbox() {
	echo "正在卸载singbox..."
	# Stop and disable sing-box service
	systemctl stop sing-box
	systemctl disable sing-box > /dev/null 2>&1

	# Remove files
	rm /etc/systemd/system/sing-box.service
	rm /root/reality.json
	rm /root/sing-box
	rm /root/public.key.b64
	rm -rf /root/singbox
	colorEcho $RED "singbox已卸载完成!"
}

Show_Link() {

	# Get current listen port
	current_listen_port=$(jq -r '.inbounds[0].listen_port' /root/reality.json)

	# Get current server name
	current_server_name=$(jq -r '.inbounds[0].tls.server_name' /root/reality.json)

	# Get the UUID
	uuid=$(jq -r '.inbounds[0].users[0].uuid' /root/reality.json)

	# Get the public key from the file, decoding it from base64
	public_key=$(base64 --decode /root/public.key.b64)
	
	# Get the short ID
	short_id=$(jq -r '.inbounds[0].tls.reality.short_id[0]' /root/reality.json)
	
	# Retrieve the server IP address
	server_ip=$(cat /root/singbox/ip)
	
	# Generate the link
	if [[ "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        server_link="vless://$uuid@$server_ip:$listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#$node_name"
	elif [[ "$server_ip" =~ ^([0-9a-fA-F:]+)$ ]]; then 
        server_link="vless://$uuid@[$server_ip]:$listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#$node_name"
	else
	    colorEcho $RED "没有获取到有效ip！"
	fi
    colorEcho $BLUE "${BLUE}reality订阅链接${PLAIN}：${server_link}"	
	echo ""
    echo ""
	colorEcho $YELLOW "reality节点二维码（可直接扫码导入到v2rayN、shadowrocket等客户端...）："
	qrencode -o - -t utf8 -s 1 ${server_link}
	exit 0

}

Modify_singboxconfig() {
	# Get current listen port
	listen_port=$(jq -r '.inbounds[0].listen_port' /root/reality.json)
	#echo $listen_port

	# Get current server name
	server_name=$(jq -r '.inbounds[0].tls.server_name' /root/reality.json)
	#echo $server_name
	
	# Get current server port
	#server_port=$(jq -r '.inbounds[0].tls.reality.handshake.server_port' /root/reality.json)
	#echo $server_port

	# Get the UUID
	uuid=$(jq -r '.inbounds[0].users[0].uuid' /root/reality.json)
	#echo $uuid

	# Get the public key from the file, decoding it from base64
	public_key=$(base64 --decode /root/public.key.b64)
	#echo $public_key
	
	# Get the private key
	private_key=$(jq -r '.inbounds[0].tls.reality.private_key' /root/reality.json)
	#echo $private_key
	
	# Get the short ID
	short_id=$(jq -r '.inbounds[0].tls.reality.short_id[0]' /root/reality.json)
	#echo $short_id
	
	# Retrieve the server IP address
	server_ip=$(cat /root/singbox/ip)
	#echo $server_ip
	
	# Retrieve the server nodename
	node_name=$(cat /root/singbox/name)
	#echo $node_name
	
    # Generate uuid
	echo ""
	read -p "是否需要重新生成UUID（0：保持不变；1：重新生成）:" new_uuid
	if [[ $new_uuid == 1 ]]; then
	    echo ""
		echo "正在重新生成UUID...:" uuid
		/root/sing-box generate uuid > /root/singbox/uuid
		uuid=`cat /root/singbox/uuid`
		colorEcho $BLUE "UUID：$uuid"
	else
	    colorEcho $BLUE "uuid保持不变!" 
	fi
	
	# Generate nodename
	echo ""
	read -p "是否需要重新给节点命名（0：保持不变；1：重新命名）:" new_name
	if [[ $new_name == 1 ]]; then	
	    echo ""
		read -p "请输入您的节点名称，如果留空将保持默认：" node_name
		[[ -z "$node_name" ]] && node_name="Reality(by小企鹅)"
		colorEcho $BLUE "节点名称：$node_name"
		echo "$node_name" > /root/singbox/name
    else
	    colorEcho $BLUE "节点名称保持不变!" 
	fi
	
	# Generate key pair
	echo ""
	read -p "是否需要重新生成密钥（0：保持不变；1：重新生成）:" new_key
	if [[ $new_key == 1 ]]; then
	    echo ""
        echo "正在重新生成私钥和公钥，请妥善保管好："
	    key_pair=$(/root/sing-box generate reality-keypair)
	    # Extract private key and public key
	    private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
	    public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
        colorEcho $BLUE "$private_key"
        colorEcho $BLUE "$public_key"
	    # Save the public key in a file using base64 encoding
	    echo "$public_key" | base64 > /root/public.key.b64		
	else
	    colorEcho $BLUE "密钥保持不变!" 
	fi
	
    # Retrieve the server IP address
	echo ""
	read -p "是否需要更换节点ip（0：保持不变；1：重新选择）:" CHAIP
	if [[ $CHAIP == 1 ]]; then	
		# 尝试获取 IP 地址
		LOCAL_IPv4=$(curl -s -4 https://api.ipify.org)
		LOCAL_IPv6=$(curl -s -6 https://api64.ipify.org)
		# 检查 IPv是否存在且合法
		if [[ -n "$LOCAL_IPv4" && "$LOCAL_IPv4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

			# 检查 IPv6 是否存在且合法
			if [[ -n "$LOCAL_IPv6" && "$LOCAL_IPv6" =~ ^([0-9a-fA-F:]+)$ ]]; then
				colorEcho $YELLOW "本机 IPv4 地址："$LOCAL_IPv4""		    
				colorEcho $YELLOW "本机 IPv6 地址："$LOCAL_IPv6""
				read -p "请确定你的节点ip，默认ipv4（0：ipv4；1：ipv6）:" USER_IP
				if [[ $USER_IP == 1 ]]; then
					server_ip=$LOCAL_IPv6
					colorEcho $BLUE "节点ip："$server_ip""				
				else
					server_ip=$LOCAL_IPv4
					colorEcho $BLUE "节点ip："$server_ip""						
				fi								
			else
				colorEcho $YELLOW "本机仅有 IPv4 地址："$LOCAL_IPv4""		
				server_ip=$LOCAL_IPv4
				colorEcho $BLUE "节点ip："$server_ip""
			fi
		else
			if [[ -n "$LOCAL_IPv6" && "$LOCAL_IPv6" =~ ^([0-9a-fA-F:]+)$ ]]; then
				colorEcho $YELLOW "本机仅有 IPv6 地址："$LOCAL_IPv6""		
				server_ip=$LOCAL_IPv6
				colorEcho $BLUE "节点ip："$server_ip""
			else
				colorEcho $RED "未能获取到有效的公网 IP 地址。"		
			fi
		fi
		# 将 IP 地址写入文件
		echo "$server_ip" > /root/singbox/ip
    else
	    colorEcho $BLUE "节点ip保持不变!"  		
    fi


	# Ask for listen port
	echo ""
	read -p "是否需要更换端口（0：保持不变；1：更换端口）:" new_port
	if [[ $new_port == 1 ]]; then	
		while true
		do
		    echo ""
			read -p "请设置singbox的端口号[1025-65535]，不输入则随机生成:" listen_port
			[[ -z "$listen_port" ]] && listen_port=`shuf -i1025-65000 -n1`
			if [[ "${listen_port:0:1}" = "0" ]]; then
				echo -e "${RED}端口不能以0开头${PLAIN}"
				exit 1
			fi
			expr $listen_port + 0 &>/dev/null
			if [[ $? -eq 0 ]]; then
				if [[ $listen_port -ge 1025 ]] && [[ $listen_port -le 65535 ]]; then
					echo "$listen_port" > /root/singbox/port				
					colorEcho $BLUE "端口号：$listen_port"
					# open port 
					echo ""
					echo "正在开启$listen_port端口..."	
					if [ -x "$(command -v firewall-cmd)" ]; then							  
						firewall-cmd --permanent --add-port=${listen_port}/tcp > /dev/null 2>&1
						firewall-cmd --permanent --add-port=${listen_port}/udp > /dev/null 2>&1
						firewall-cmd --reload > /dev/null 2>&1
						colorEcho $YELLOW "$listen_port端口已成功开启"
					elif [ -x "$(command -v ufw)" ]; then								  
						ufw allow ${listen_port}/tcp > /dev/null 2>&1
						ufw allow ${listen_port}/udp > /dev/null 2>&1
						ufw reload > /dev/null 2>&1
						colorEcho $YELLOW "$listen_port端口已成功开启"
					else
						colorEcho $RED "无法配置防火墙规则。请手动配置以确保新singbox端口可用!"
					fi
					break
				else
					colorEcho $RED "输入错误，端口号为1025-65535的数字"
				fi
			else
				colorEcho $RED "输入错误，端口号为1025-65535的数字"
			fi
		done
	else
	    colorEcho $BLUE "端口保持不变!"  
	fi

	
	# Ask for server name (sni)
	echo ""
	read -p "是否需要更换目标网站（0：保持不变；1：重新输入）:" new_sni
	if [[ $new_sni == 1 ]]; then	
		echo ""
		read -p "请输入您的 dest 地址并确保该域名在国内的连通性（例如：www.amazon.com），如果留空将随机生成：" DEST
		if [[ -z "$DEST" ]]; then
			# 反复随机选择域名，直到符合条件
			while true; do
				# 调用函数获取随机域名
				domain=$(random_website)
				# 使用 OpenSSL 检查域名的 TLS 信息
				check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
				# 如果 check_num 等于 3，表示符合条件，跳出循环
				if [ "$check_num" -eq 3 ]; then
					DEST="$domain"
					break
				fi
			done
			
			echo $DEST > /root/singbox/dest		
			echo $DEST > /root/singbox/servername
			server_name=`cat /root/singbox/servername`
			colorEcho $BLUE "选中的符合条件的网站是： $server_name"	
		else
			echo "正在检查 \"${DEST}\" 是否支持 TLSv1.3与h2"
			# 检查是否支持 TLSv1.3与h2
			check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${DEST}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
			if [[ ${check_num} -eq 3 ]]; then
				echo $DEST > /root/singbox/dest		
				echo $DEST > /root/singbox/servername
				server_name=`cat /root/singbox/servername`
				colorEcho $YELLOW "目标网址：\"${DEST}\" 支持 TLSv1.3 与 h2"
			else
				colorEcho $YELLOW "目标网址：\"${DEST}\" 不支持 TLSv1.3 与 h2，将在默认域名组中随机挑选域名"
				# 反复随机选择域名，直到符合条件
				while true; do
					# 调用函数获取随机域名
					domain=$(random_website)
					# 使用 OpenSSL 检查域名的 TLS 信息
					check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${domain}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
					# 如果 check_num 等于 3，表示符合条件，跳出循环
					if [ "$check_num" -eq 3 ]; then
						DEST="$domain"
						break
					fi
				done
				
				echo $DEST > /root/singbox/dest		
				echo $DEST > /root/singbox/servername
				server_name=`cat /root/singbox/servername`
				colorEcho $BLUE "选中的符合条件的网站是： $server_name"				

			fi	   
		fi	
    else
	    colorEcho $BLUE"目标网址保持不变!"  
	fi

	# Generate short_id
	echo ""
	read -p "是否需要重新生成shortID:（0：保持不变；1：重新生成）" new_sid
	if [[ $new_sid == 1 ]]; then	
	    echo ""
		echo "正在重新生成shortID..."
		/root/sing-box generate rand --hex 8 > /root/singbox/sid
		short_id=`cat /root/singbox/sid`
		colorEcho $BLUE  "shortID：$short_id"
	else
	    colorEcho $BLUE "shortID保持不变!"  
	fi
	echo ""

	# Modify reality.json with new settings
	#jq --arg listen_port "$listen_port" --arg server_name "$server_name" '.inbounds[0].listen_port = ($listen_port | tonumber) | .inbounds[0].tls.server_name = $server_name | .inbounds[0].tls.reality.handshake.server = $server_name' /root/reality.json > /root/reality_modified.json
jq -n --arg listen_port "$listen_port" --arg server_name "$server_name" --arg private_key "$private_key" --arg short_id "$short_id" --arg uuid "$uuid" --arg server_ip "$server_ip" '{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": ($listen_port | tonumber),
      "sniff": true,
      "sniff_override_destination": true,
      "domain_strategy": "ipv4_only",
      "users": [
        {
          "uuid": $uuid,
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": $server_name,
          "reality": {
          "enabled": true,
          "handshake": {
            "server": $server_name,
            "server_port": 443
          },
          "private_key": $private_key,
          "short_id": [$short_id]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}' > /root/reality.json
  
	# Restart sing-box service
	systemctl restart sing-box
	echo ""
	
	# Generate the link
	if [[ "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        server_link="vless://$uuid@$server_ip:$listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#$node_name"
	elif [[ "$server_ip" =~ ^([0-9a-fA-F:]+)$ ]]; then 
        server_link="vless://$uuid@[$server_ip]:$listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#$node_name"
	else
	    colorEcho $RED "没有获取到有效ip！"
	fi
    colorEcho $BLUE "${BLUE}reality订阅链接${PLAIN}：${server_link}"	
	echo ""
    echo ""
	colorEcho $YELLOW "reality节点二维码（可直接扫码导入到v2rayN、shadowrocket等客户端...）："
	qrencode -o - -t utf8 -s 1 ${server_link}
	exit 0


}


setFirewall() {
    echo ""
	echo "正在开启$PORT端口..."	
    if [ -x "$(command -v firewall-cmd)" ]; then							  
        firewall-cmd --permanent --add-port=${PORT}/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=${PORT}/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
		colorEcho $YELLOW "$PORT端口已成功开启"
	elif [ -x "$(command -v ufw)" ]; then								  
        ufw allow ${PORT}/tcp > /dev/null 2>&1
        ufw allow ${PORT}/udp > /dev/null 2>&1
	    ufw reload > /dev/null 2>&1
		colorEcho $YELLOW "$PORT端口已成功开启"
    else
	    echo "无法配置防火墙规则。请手动配置以确保新xray端口可用!"
    fi

}

start_singbox() {
    res=`status_singbox`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}singbox未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl restart sing-box
    sleep 2
    port=`grep -o '"listen_port": [0-9]*' /root/reality.json | awk '{print $2}'`
    res=`ss -ntlp| grep ${port} | grep sing-box`
    if [[ "$res" = "" ]]; then
        colorEcho $RED "singbxo启动失败，请检查端口是否被占用！"
    else
        colorEcho $BLUE "singbox启动成功！"
    fi
}

restart_singbox() {
    res=`status_singbox`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}singbox未安装，请先安装！${PLAIN}"
        return
    fi

    stop_singbox
    start_singbox
}

stop_singbox() {
    res=`status_singbox`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}singbox未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl stop sing-box
    colorEcho $BLUE "singbox停止成功"
}

menu() {
    clear
    bash -c "$(curl -s -L https://raw.githubusercontent.com/yirenchengfeng1/linux/main/reality.sh)"
}

	
Singbox() {
    clear
    echo "##################################################################"
    echo -e "#                   ${RED}Reality一键安装脚本${PLAIN}                                    #"
    echo -e "# ${GREEN}作者${PLAIN}: 爱分享的小企鹅                                                     #"
    echo -e "# ${GREEN}网址${PLAIN}: hhttp://www.youtube.com/@aifenxiangdexiaoqie                       #"
	echo -e "# ${GREEN}VPS选购攻略${PLAIN}：https://lovetoshare.top/archives/3.html                     #"
	echo -e "# ${GREEN}年付10美金VPS推荐${PLAIN}：https://my.racknerd.com/aff.php?aff=9734&pid=838      #"	
    echo "##################################################################"

    echo -e "  ${GREEN}  <Singbox内核版本>  ${YELLOW}"	
    echo -e "  ${GREEN}1.${PLAIN}  安装singbox"
    echo -e "  ${GREEN}2.${PLAIN}  更新singbox"
    echo -e "  ${GREEN}3.${RED}  卸载singbox${PLAIN}"
    echo " -------------"		
	echo -e "  ${GREEN}4.${PLAIN}  搭建VLESS-Vision-uTLS-REALITY（singbox）"
    echo -e "  ${GREEN}5.${PLAIN}  查看reality链接"
    echo -e "  ${GREEN}6.  ${RED}修改reality配置${PLAIN}"		
    echo " -------------"
    echo -e "  ${GREEN}7.${PLAIN}  启动singbox"
    echo -e "  ${GREEN}8.${PLAIN}  重启singbox"
    echo -e "  ${GREEN}9.${PLAIN}  停止singbox"
    echo " -------------"
    echo -e "  ${GREEN}10.${PLAIN}  返回上一级菜单"	
    echo -e "  ${GREEN}0.${PLAIN}  退出"
    echo -n " 当前singbox状态："
	statusText_singbox
    echo 

    read -p " 请选择操作[0-10]：" answer
    case $answer in
        0)
            exit 0
            ;;
        1)
		    checkSystem
			preinstall
            installSingbox
		    Singbox
            ;;
        2)
            Switch_singboxcore
			Singbox
            ;;
        3)
            UninstallSingbox
            ;;
        4)
            install_singbox
            ;;
        5)
			Show_Link  
            ;;
        6)
            Modify_singboxconfig     
            ;;			
        7)
            start_singbox
			Singbox
            ;;
        8)
            restart_singbox
			Singbox
            ;;
        9)
            stop_singbox
			Singbox
            ;;			
		10)
			menu
            ;;
        *)
            echo " 请选择正确的操作！"
            exit 1
            ;;
    esac
}

Singbox
