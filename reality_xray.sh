#!/bin/bash
# REALITY一键安装脚本
# Author: YouTube频道<https://www.youtube.com/@aifenxiangdexiaoqie>

RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'

NAME="xray"
CONFIG_FILE="/usr/local/etc/${NAME}/config.json"
SERVICE_FILE="/etc/systemd/system/${NAME}.service"

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

status() {
    export PATH=/usr/local/bin:$PATH
    cmd="$(command -v xray)"
    if [[ "$cmd" = "" ]]; then
        echo 0
        return
    fi
    if [[ ! -f $CONFIG_FILE ]]; then
        echo 1
        return
    fi
    port=`grep -o '"port": [0-9]*' $CONFIG_FILE | awk '{print $2}'`
    res=`ss -ntlp| grep ${port} | grep xray`
    if [[ -z "$res" ]]; then
        echo 2
    else
        echo 3
    fi
}

statusText() {
    res=`status`
    case $res in
        2)
            echo -e ${GREEN}已安装${PLAIN} ${RED}未运行${PLAIN}
            ;;
        3)
            echo -e ${GREEN}已安装${PLAIN} ${GREEN}正在运行${PLAIN}
            ;;
        *)
            echo -e ${RED}未安装${PLAIN}
            ;;
    esac
}

preinstall() {
    $PMT clean all
    [[ "$PMT" = "apt" ]] && $PMT update
    echo ""
    colorEcho $BULE " 安装必要软件"
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

    if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
        setenforce 0
    fi
}


# 安装 Xray内核
installXray() {
    
    colorEcho $BLUE "正在安装 Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
	}

removeXray() {
    
    colorEcho $RED "正在卸载 Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
	rm -rf /etc/systemd/system/xray.service > /dev/null 2>&1
    rm -rf /etc/systemd/system/xray@.service > /dev/null 2>&1
    rm -rf /usr/local/bin/xray > /dev/null 2>&1
    rm -rf /usr/local/etc/xray > /dev/null 2>&1
    rm -rf /usr/local/share/xray > /dev/null 2>&1
    rm -rf /var/log/xray > /dev/null 2>&1
	
}




# 填写或生成 UUID
getuuid() {
    echo ""
    echo "正在生成UUID..."
	/usr/local/bin/xray uuid > /usr/local/etc/xray/uuid
	USER_UUID=`cat /usr/local/etc/xray/uuid`
    colorEcho $BLUE "UUID：$USER_UUID"
	echo ""
}

# 指定节点名称
getname() {
	read -p "请输入您的节点名称，如果留空将保持默认：" USER_NAME
	[[ -z "$USER_NAME" ]] && USER_NAME="Reality(by小企鹅)"
    colorEcho $BLUE "节点名称：$USER_NAME"
	echo "$USER_NAME" > /usr/local/etc/xray/name
	echo ""
		
}

# 生成私钥和公钥
getkey() {
    echo "正在生成私钥和公钥，请妥善保管好..."
	/usr/local/bin/xray x25519 > /usr/local/etc/xray/key
	private_key=$(cat /usr/local/etc/xray/key | head -n 1 | awk '{print $3}')
	public_key=$(cat /usr/local/etc/xray/key | sed -n '2p' | awk '{print $3}')
	echo "$private_key" > /usr/local/etc/xray/privatekey
	echo "$public_key" > /usr/local/etc/xray/publickey
	KEY=`cat /usr/local/etc/xray/key`
	colorEcho $BLUE "$KEY"
    echo ""
}

getip() {
    LOCAL_IP=$(curl -s https://api.ipify.org)
	echo "$LOCAL_IP" > /usr/local/etc/xray/ip
	colorEcho $YELLOW "本机ip："$LOCAL_IP""
}

getport() {
    echo ""
    while true
    do
        read -p "请设置XRAY的端口号[1025-65535]，不输入则随机生成:" PORT
        [[ -z "$PORT" ]] && PORT=`shuf -i1025-65000 -n1`
        if [[ "${PORT:0:1}" = "0" ]]; then
            echo -e "${RED}端口不能以0开头${PLAIN}"
            exit 1
        fi
        expr $PORT + 0 &>/dev/null
        if [[ $? -eq 0 ]]; then
            if [[ $PORT -ge 1025 ]] && [[ $PORT -le 65535 ]]; then
	            echo "$PORT" > /usr/local/etc/xray/port				
                colorEcho $BLUE "端口号：$PORT"
                break
            else
                colorEcho $RED "输入错误，端口号为1025-65535的数字"
            fi
        else
            colorEcho $RED "输入错误，端口号为1025-65535的数字"
        fi
    done
	
}

setFirewall() {
    if [ -x "$(command -v firewall-cmd)" ]; then							  
        firewall-cmd --permanent --add-port=${PORT}/tcp
        firewall-cmd --permanent --add-port=${PORT}/udp
        firewall-cmd --reload
	elif [ -x "$(command -v ufw)" ]; then								  
        ufw allow ${PORT}/tcp
        ufw allow ${PORT}/udp
	    ufw reload
    else
	    echo "无法配置防火墙规则。请手动配置以确保新xray端口可用!"
    fi

}

# 生成或获取 dest
getdest() {
    echo ""
    read -p "请输入您的 dest 地址并确保该域名在国内的连通性（例如：www.amazon.com），如果留空将保持默认：" USER_DEST
	if [[ -z "$USER_DEST" ]]; then
		USER_DEST="www.amazon.com"
		echo $USER_DEST:443 > /usr/local/etc/xray/dest
		echo $USER_DEST > /usr/local/etc/xray/servername
		colorEcho $BLUE "目标网址： $USER_DEST"	
	else
		echo "正在检查 \"${USER_DEST}\" 是否支持 TLSv1.3与h2"
		# 检查是否支持 TLSv1.3与h2
        check_num=$(echo QUIT | stdbuf -oL openssl s_client -connect "${USER_DEST}:443" -tls1_3 -alpn h2 2>&1 | grep -Eoi '(TLSv1.3)|(^ALPN\s+protocol:\s+h2$)|(X25519)' | sort -u | wc -l)
		if [[ ${check_num} -eq 3 ]]; then
			echo "\"${USER_DEST}\" 支持 TLSv1.3 与 h2"
			echo $USER_DEST:443 > /usr/local/etc/xray/dest
		    echo $USER_DEST > /usr/local/etc/xray/servername
		    colorEcho $BLUE "目标网址： $USER_DEST"	
		else
			echo "\"${USER_DEST}\" 不支持 TLSv1.3 与 h2，将使用默认域名www.amazon.com"
		    USER_DEST="www.amazon.com"
		    echo $USER_DEST:443 > /usr/local/etc/xray/dest
		    echo $USER_DEST > /usr/local/etc/xray/servername
		    colorEcho $BLUE "目标网址： $USER_DEST"	
		fi	   
	fi

	
}


# 生成 short ID
getsid() {

    echo ""
    echo "正在生成shortID..."
    USER_SID=$(openssl rand -hex 8)
    echo $USER_SID > /usr/local/etc/xray/sid
    colorEcho $BLUE "shortID： $USER_SID"
    echo ""

}


# 创建配置文件 config.json
generate_config() {
    echo "创建配置文件 config.json..."
    cat << EOF > /usr/local/etc/xray/config.json
{
    "log": {
        "loglevel": "debug"
    },
    "inbounds": [
        {
            "port": $(cat /usr/local/etc/xray/port), 
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$(cat /usr/local/etc/xray/uuid)", 
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "$(cat /usr/local/etc/xray/dest)", 
                    "serverNames": [
                        "$(cat /usr/local/etc/xray/servername)"   
                    ],
                    "privateKey": "$(cat /usr/local/etc/xray/privatekey)",
                    "shortIds": [
                        "",
                        "$(cat /usr/local/etc/xray/sid)" 
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF
}

start() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}xray未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl restart ${NAME}
    sleep 2
    port=`grep -o '"port": [0-9]*' $CONFIG_FILE | awk '{print $2}'`
    res=`ss -ntlp| grep ${port} | grep xray`
    if [[ "$res" = "" ]]; then
        colorEcho $RED "xray启动失败，请检查端口是否被占用！"
    else
        colorEcho $BLUE "xray启动成功！"
    fi
}

restart() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}xray未安装，请先安装！${PLAIN}"
        return
    fi

    stop
    start
}

stop() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        echo -e "${RED}xray未安装，请先安装！${PLAIN}"
        return
    fi
    systemctl stop ${NAME}
    colorEcho $BLUE "xray停止成功"
}


# 输出 VLESS 链接
generate_link() {

    LINK="vless://$(cat /usr/local/etc/xray/uuid)@$(cat /usr/local/etc/xray/ip):$(cat /usr/local/etc/xray/port)?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$(cat /usr/local/etc/xray/servername)&fp=chrome&pbk=$(cat /usr/local/etc/xray/publickey)&sid=$(cat /usr/local/etc/xray/sid)&type=tcp&headerType=none#$(cat /usr/local/etc/xray/name)"
    echo -e " ${BLUE}订阅链接${PLAIN}： ${LINK}"	
	qrencode -o - -t utf8 ${LINK}
    qrencode -o /tmp/reality.png -s 10 ${LINK}
	colorEcho $BLUE " 订阅二维码已保存在/tmp/reality.png，请下载使用..."				  
}	

menu() {
    clear
    echo "##################################################################"
    echo -e "#                   ${RED}Reality一键安装脚本${PLAIN}                                    #"
    echo -e "# ${GREEN}作者${PLAIN}: 爱分享的小企鹅                                                     #"
    echo -e "# ${GREEN}网址${PLAIN}: hhttp://www.youtube.com/@aifenxiangdexiaoqie                       #"
	echo -e "# ${GREEN}VPS选购攻略${PLAIN}：https://lovetoshare.top/archives/3.html                     #"
	echo -e "# ${GREEN}年付10美金VPS推荐${PLAIN}：https://my.racknerd.com/aff.php?aff=9734&pid=838      #"	
    echo "##################################################################"

    echo -e "  ${GREEN}1.${PLAIN}   安装VLESS-Vision-uTLS-REALITY"
    echo " -------------"
    echo -e "  ${GREEN}2.${PLAIN}  更新xray内核"
    echo -e "  ${GREEN}3.  ${RED}卸载脚本${PLAIN}"
    echo " -------------"
    echo -e "  ${GREEN}4.${PLAIN}  启动xray"
    echo -e "  ${GREEN}5.${PLAIN}  重启xray"
    echo -e "  ${GREEN}6.${PLAIN}  停止xray"
    echo " -------------"
    echo -e "  ${GREEN}7.${PLAIN}  查看vless链接"
    echo -e "  ${GREEN}8.  ${RED}修改配置${PLAIN}"	
    echo " -------------"
    echo -e "  ${GREEN}0.${PLAIN}   退出"
    echo -n " 当前状态："
	statusText
    echo 

    read -p " 请选择操作[0-8]：" answer
    case $answer in
        0)
            exit 0
            ;;
        1)
		    checkSystem
            preinstall
	        installXray
			getuuid
			getname
			getkey
			getip
			getport
			getdest
			getsid
			setFirewall
			generate_config
		    restart
			generate_link
            ;;
        2)
	        installXray
            ;;
        3)
            removeXray
            ;;
        4)
            start
            ;;
        5)
            restart
            ;;
        6)
            stop
            ;;
        7)
			generate_link  
            ;;
        8)
			getuuid
			getname
			getkey
			getip
			getport
			getdest
			getsid
			setFirewall			
			generate_config
		    restart
			generate_link      
            ;;
        *)
            echo " 请选择正确的操作！"
            exit 1
            ;;
    esac
}

menu
