#!/bin/bash
# VPS日常管理一键脚本
# Author: 爱分享的小企鹅


RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'

BASE=`pwd`
# 获取当前操作系统版本
OS=`hostnamectl | grep -i system | cut -d: -f2`

# 获取ip地址
    ipv4=$(curl -s ipv4.ip.sb)
    ipv6=$(curl -s ipv6.ip.sb)


#install necessary lib
yum_install(){
    if [ "$system_str" = "0" ]; then
    yum -y install wget curl lrzsz net-tools htop iftop vnstat ncdu
	echo -e "  ${GREEN}已安装wget、curl、lrzsz、net-tools等命令   ${PLAIN}"
	sleep 2
    else
    apt install -y wget curl lrzsz net-tools htop iftop vnstat ncdu
	echo -e "  ${GREEN}已安装wget、curl、lrzsz、net-tools等命令   ${PLAIN}"	
	sleep 2	
    fi
}

yum_remove(){
    if [ "$system_str" = "0" ]; then
    yum -y remove wget curl lrzsz net-tools htop iftop vnstat ncdu
	yum clean all
	echo -e "  ${GREEN}已卸载wget、curl、lrzsz、net-tools等命令   ${PLAIN}"	
	sleep 2    
	else
    apt remove -y wget curl lrzsz net-tools htop iftop vnstat ncdu
	apt-get clean
	echo -e "  ${GREEN}已卸载wget、curl、lrzsz、net-tools等命令   ${PLAIN}"	
	sleep 2    
	fi
}

man_tools() {
    while true
       do  
	     clear
         echo "1. 确认安装有关命令"
         echo "------------------------"
         echo "2. 卸载安装的命令"
         echo "------------------------"	   
         echo "0. 返回上一级菜单"
         echo "------------------------"	 		 
         read -p "请输入你的选择: " choice
          case $choice in
		     0)
               break 
                 ;;
		     1)
            yum_install
		         ;;
		     2)
			yum_remove
			     ;;
             *)
            echo -e "$RED 请选择正确的操作！${PLAIN}"
           ;;
		esac

    done
		
}



dis_ip() {
        echo -e "  ${GREEN}当前系统IPv4地址：$ipv4   ${PLAIN}"
        echo -e "  ${GREEN}当前系统IPv6地址：$ipv6   ${PLAIN}"
	    while true
        do
          read -p "请输入任意按键返回上一级菜单: " sub_choice
          case $sub_choice in
	         *)
               break 
                 ;;
          esac 
        done
}


colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}


check_system(){
    if grep -Eqi "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then
        system_str="0"
    elif  grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        system_str="1"
    elif  grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then
        system_str="2"
    else
        echo "This Script must be running at the CentOS or Ubuntu or Debian!"
        exit 1
    fi
}

update_app(){
    if [ "$system_str" = "0" ]; then
    yum -y update
    else
    apt -y update
    fi
}

powercontrol() {
	    echo "选择要执行的操作:"
		echo -e "  ${RED}1. 关机${PLAIN}"
		echo -e "  ${RED}2. 重启${PLAIN}"
		echo -e "  ${RED}0. 返回上一级菜单${PLAIN}"
        read -p "输入选项 (1/2): " choice
        if [ "$choice" = "1" ]; then
              shutdown -h now  
        elif [ "$choice" = "2" ]; then
              shutdown -r now  
        else
              echo "返回！"
			  sleep 2
        fi
}



get_time() {
	   clear    
	   current_timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
       current_time=$(date +"%Y-%m-%d %H:%M:%S")
	   
}

spead_ssh() {
    clear
        # 询问用户是否继续
    while true
       do 
	  
         echo "1. 确认提升SSH连接速度"
         echo "------------------------"
         echo "0. 返回上一级选单"
         echo "------------------------"	   
         read -p "请输入你的选择: " choice
          case $choice in
		     0)
               break 
                 ;;
		     1)
           
           # 备份原始SSH配置文件
           if [ -f "/etc/ssh/sshd_config" ]; then
               cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
           else
               echo "未找到SSH配置文件！"
               exit 1
           fi
           sed -i -e '/UseDNS/s/yes/no/g; /^#.*UseDNS/s/#//g' /etc/ssh/sshd_config
           sed -i -e '/^#.*GSSAPIAuthentication/s/yes/no/g' /etc/ssh/sshd_config

           if [ -x "$(command -v systemctl)" ]; then
               systemctl restart sshd
           elif [ -x "$(command -v service)" ]; then
                 service sshd restart
           else
               echo "无法重启SSH服务。请手动重启SSH服务以使更改生效。"
           fi
		   echo -e "  ${GREEN}优化完成，请输入0返回上级菜单${PLAIN}"
		 
           ;;
		 *)
            echo -e "$RED 请选择正确的操作！${PLAIN}"
           ;;
		esac

    done
		

}

ssh_login() {
      

     cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak  
    while true
       do  
          clear	   
	      echo "1. 生成SSH密钥"
	      echo "------------------------"
          echo "2. 开启密钥登录方式"
          echo "------------------------"
          echo "3. 关闭密钥登录方式"
          echo "------------------------"
		  echo "4. 关闭密码登录方式（与云服务商有关，可能禁不了）"
          echo "------------------------"
          echo "5. 开启密码登录方式"
          echo "------------------------"
		  echo "0. 返回上一级选单"
          echo "------------------------"
	      # 询问用户是否继续
          read -p "请输入你的选择: " choice
		  case $choice in
		     0)  
	           break 
                 ;;
		     1)
			 
				lrzsz_exist=$(which lrzsz)

			if [ -z "$lrzsz_exist" ]; then


				  if [ "$system_str" = "0" ]; then
						yum install -y lrzsz
				  else
						apt install -y lrzsz
				  
				  fi

			fi
			   
				ssh-keygen -t rsa -b 2048
				cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys 
			
				sz /root/.ssh/id_rsa
                echo -e "  ${RED}SSH密钥已生成，请在本地保管好你的私钥！！！${PLAIN}"
	            ;;
			 2)
				sed -i 's/^\#*RSAAuthentication.*/RSAAuthentication yes/' /etc/ssh/sshd_config
				sed -i 's/^\#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

                if [ -x "$(command -v systemctl)" ]; then
                     systemctl restart sshd
					 echo -e "  ${GREEN}SSH密钥登录已开启！${PLAIN}"
					 sleep 2
                elif [ -x "$(command -v service)" ]; then
                     service sshd restart
					 echo -e "  ${GREEN}SSH密钥登录已开启！${PLAIN}"
					 sleep 2
                else
                     echo "无法重启SSH服务。请手动重启SSH服务以使更改生效。"
					 sleep 2
                fi
			    ;;
				
			 3)
			    sed -i 's/^\#*RSAAuthentication.*/RSAAuthentication no/' /etc/ssh/sshd_config
				sed -i 's/^\#*PubkeyAuthentication.*/PubkeyAuthentication no/' /etc/ssh/sshd_config
				

			
                if [ -x "$(command -v systemctl)" ]; then
                     systemctl restart sshd
					 echo -e "  ${GREEN}SSH密钥登录已关闭！${PLAIN}"
					 sleep 2
                elif [ -x "$(command -v service)" ]; then
                     service sshd restart
					 echo -e "  ${GREEN}SSH密钥登录已关闭！${PLAIN}"
					 sleep 2
                else
                     echo "无法重启SSH服务。请手动重启SSH服务以使更改生效。"
					 sleep 2
                fi
			    ;;
			 4)
			    sed -i 's/^\#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
				sed -i 's/^\#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
			
                if [ -x "$(command -v systemctl)" ]; then
                     systemctl restart sshd
					 echo -e "  ${GREEN}SSH密码登录已关闭！${PLAIN}"
					 sleep 2
                elif [ -x "$(command -v service)" ]; then
                     service sshd restart
					 echo -e "  ${GREEN}SSH密码登录已关闭！${PLAIN}"
					 sleep 2
                else
                     echo "无法重启SSH服务。请手动重启SSH服务以使更改生效。"
					 sleep 2
                fi
			    ;;	
	     	 5)
			    sed -i 's/^\#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
				sed -i 's/^\#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
			
                if [ -x "$(command -v systemctl)" ]; then
                     systemctl restart sshd
					 echo -e "  ${GREEN}SSH密码登录已开启！${PLAIN}"
					 sleep 2
                elif [ -x "$(command -v service)" ]; then
                     service sshd restart
					 echo -e "  ${GREEN}SSH密码登录已开启！${PLAIN}"
					 sleep 2
                else
                     echo "无法重启SSH服务。请手动重启SSH服务以使更改生效。"
					 sleep 2
                fi
			    ;;	
              *)
                 echo -e "$RED 请选择正确的操作！${PLAIN}"
                 
                 ;;
		    esac

    done	
}
        
man_ssh_port() {
    clear
    

	echo -e "  ${RED}请注意：更改SSH端口可能会影响远程连接。  ${PLAIN}"
    while true
       do   
             
	      echo "1. 显示当前SSH端口"
	      echo "------------------------"
          echo "2. 更改当前SSH端口"
          echo "------------------------"
          echo "0. 返回上一级选单"
          echo "------------------------"

          read -p "请输入你的选择: " choice
		  case $choice in
		     0)
               break 
                 ;;
	         1)
            ssh_port=`grep -E "^#*Port" /etc/ssh/sshd_config | awk '{print $2}'`
			echo -e "  ${GREEN}当前SSH端口：$ssh_port  ${PLAIN}"
			
                 ;;
	         2)       

			if [ -f "/etc/ssh/sshd_config" ]; then
			     cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
			else
			     echo "未找到SSH配置文件。请手动备份和更改SSH端口。"
		
			fi

			echo "系统当前已开放的TCP端口号，选择时请避开以下端口："
			netstat -tuln | awk '/^tcp/ {print $4}' | awk -F: '{print $NF}' | sort -n | uniq
			
   
            ssh_port=`grep -E "^#*Port" /etc/ssh/sshd_config | awk '{print $2}'`
			

			read -p "请输入新的SSH端口号: " new_port
			

			sed -i "/^.*Port /d" /etc/ssh/sshd_config
			
			
			echo "Port $new_port" >> /etc/ssh/sshd_config




			if [ -x "$(command -v firewall-cmd)" ]; then
		
				   firewall-cmd --permanent --zone=public --remove-port=$ssh_port/tcp
				   firewall-cmd --permanent --zone=public --add-port=$new_port/tcp
			       firewall-cmd --reload
			elif [ -x "$(command -v ufw)" ]; then
				  ufw deny $ssh_port/tcp
			      ufw allow $new_port/tcp
			      ufw reload

			else
			       echo "无法配置防火墙规则。请手动配置以确保新SSH端口可用。"
			fi
         
		

			if [ -x "$(command -v systemctl)" ]; then
			     if [ -x "$(command -v getenforce)" ]; then
			     semanage port -d -t ssh_port_t -p tcp $ssh_port
			     semanage port -a -t ssh_port_t -p tcp $new_port
				 fi
			     systemctl restart sshd
				 echo -e "  ${GREEN}修改后的端口为：$new_port${PLAIN}"
				 sleep 3
			elif [ -x "$(command -v service)" ]; then
			     if [ -x "$(command -v getenforce)" ];then
			     semanage port -d -t ssh_port_t -p tcp $ssh_port
			     semanage port -a -t ssh_port_t -p tcp $new_port
				 fi		
			     service sshd restart
				 echo -e "  ${GREEN}修改后的端口为：$new_port${PLAIN}"
				 sleep 3
			else
			     echo "无法重启SSH服务。请手动重启SSH服务以使更改生效。"
			fi
			
                 ;;  
		    *)
                echo -e "$RED 请选择正确的操作！${PLAIN}"
            
                 ;;
          esac

    done


 
}

man_firewall(){
 

		if [ -x "$(command -v firewall-cmd)" ]; then
		   fw=firewall-cmd

		elif [ -x "$(command -v ufw)" ];  then
		  fw=ufw
		else
		  echo "未检测到支持的防火墙"
		  
		fi
        clear
		while true
       do   
         
	      echo "1. 显示防火墙运行状态"
	      echo "------------------------"
          echo "2. 临时关闭防火墙"
          echo "------------------------"
		  echo "3. 开启防火墙"
          echo "------------------------"
		  echo "4. 重启防火墙"
          echo "------------------------"
		  echo "5. 防火墙已放行的端口"
          echo "------------------------"
		  echo "6. 开启指定端口"
          echo "------------------------"
		  echo "7. 关闭指定端口"
          echo "------------------------"		    
          echo "0. 返回上一级选单"
          echo "------------------------"
	      # 询问用户是否继续
          read -p "请输入你的选择: " choice
		  case $choice in
		     0)
               break 
                 ;;
		     1)
                  
		    if [ "$fw" = "firewall-cmd" ]; then
		          echo -n "防火墙运行状态："
				  firewall-cmd --state
				  sleep 3

		    elif [ "$fw" = "ufw" ]; then
		          echo -n "防火墙运行状态：`ufw status`"
				  sleep 3
			else
			     echo -n "未知的防火墙类型，建议自行开启ufw后再尝试..."
		    fi
			clear
			    ;;
		     2)
                  
		    if [ "$fw" = "firewall-cmd" ]; then
		          systemctl stop firewalld
				  if [ $? -eq 0 ]; then
                       echo "防火墙已停止"
					   sleep 3
                  else
                       echo "防火墙停止失败"
					   sleep 3
                  fi

		    elif [ "$fw" = "ufw" ]; then
		        systemctl stop ufw
		        if [ $? -eq 0 ]; then
                       echo "防火墙已停止"
					   sleep 3
                else
                       echo "防火墙停止失败"
					   sleep 3
                fi
			else
			     echo -n "未知的防火墙类型，建议自行开启ufw后再尝试..."
		    fi
			    clear
			    ;;
		    3)

		    if [ "$fw" = "firewall-cmd" ]; then
		          systemctl start firewalld
				  if [ $? -eq 0 ]; then
                       echo "防火墙已开启"
					   sleep 3
                  else
                       echo "防火墙开启失败"
					   sleep 3
                  fi

		    elif [ "$fw" = "ufw" ]; then
		        systemctl start ufw
		        if [ $? -eq 0 ]; then
                       echo "防火墙已开启"
					   sleep 3
                else
                       echo "防火墙开启失败"
					   sleep 3
                fi
			else
			     echo -n "未知的防火墙类型，建议自行开启ufw后再尝试..."
		    fi
			clear
			    ;;
             4)

		    if [ "$fw" = "firewall-cmd" ]; then
		          systemctl restart firewalld
				  if [ $? -eq 0 ]; then
                       echo "防火墙已重启"
					   sleep 3
                  else
                       echo "防火墙重启失败"
					   sleep 3
                  fi

		  
		    elif [ "$fw" = "ufw" ]; then
		        systemctl restart ufw
		        if [ $? -eq 0 ]; then
                       echo "防火墙已重启"
					   sleep 3
                else
                       echo "防火墙重启失败"
					   sleep 3
                fi
			else
			     echo -n "未知的防火墙类型，建议自行开启ufw后再尝试..."
		    fi
			clear
			    ;;
				
		    5)

		    if [ "$fw" = "firewall-cmd" ]; then
		         firewall-cmd --list-ports
		  
		    elif [ "$fw" = "ufw" ]; then
                   ufw status numbered  
			else
			     echo -n "未知的防火墙类型，建议自行开启ufw后再尝试..."
		    fi
			    ;;
		    6)
                  
			read -p "请输入需要开启的端口号：" PORT
	
			read -p "请输入协议类型 (tcp/udp/both):" PROTOCOL

			if [ "$fw" = "firewall-cmd" ]; then
			  if [ "$PROTOCOL" = "both" ]; then
				firewall-cmd --permanent --add-port=${PORT}/tcp
				firewall-cmd --permanent --add-port=${PORT}/udp
			  else
				firewall-cmd --permanent --add-port=${PORT}/${PROTOCOL}
			  fi
			    firewall-cmd --reload
			    echo "端口 $PORT ($PROTOCOL) 已开启"
				sleep 3
		
			elif [ "$fw" = "ufw" ]; then
			  if [ "$PROTOCOL" = "both" ]; then
				ufw allow ${PORT}/tcp
				ufw allow ${PORT}/udp
			  else
				ufw allow ${PORT}/${PROTOCOL}
			  fi
			    ufw reload
			    echo "端口 $PORT ($PROTOCOL) 已开启"
				sleep 3	    
            else
			     echo -n "未知的防火墙类型，建议自行开启ufw后再尝试..."
			fi

			    ;;	
				
		    7)


			read -p "请输入需要关闭的端口号：" PORT
	
			read -p "请输入协议类型 (tcp/udp/both):" PROTOCOL

			if [ "$fw" = "firewall-cmd" ]; then
			  if [ "$PROTOCOL" = "both" ]; then
				firewall-cmd --permanent --remove-port=${PORT}/tcp
				firewall-cmd --permanent --remove-port=${PORT}/udp
			  else
				firewall-cmd --permanent --remove-port=${PORT}/${PROTOCOL}
			  fi
			    firewall-cmd --reload
			    echo "端口 $PORT ($PROTOCOL) 已关闭"
				sleep 3

			elif [ "$fw" = "ufw" ]; then
			  if [ "$PROTOCOL" = "both" ]; then
				ufw delete allow ${PORT}/tcp
				ufw delete allow ${PORT}/udp
			  else
				ufw delete allow ${PORT}/${PROTOCOL}
			  fi
			    ufw reload
			    echo "端口 $PORT ($PROTOCOL) 已关闭"
				sleep 3
             else
			     echo -n "未知的防火墙类型，建议自行开启ufw后再尝试..."
			fi


			    ;;	
			
			
		     *) 
			 echo -e "$RED 请选择正确的操作！${PLAIN}"
            
                 ;;
          esac

    done
			
			
}


change_timezone() {
       get_time
	   echo "系统时间信息"
       echo "当前系统时区：$current_timezone"
       echo "当前系统时间：$current_time"
       echo ""
       echo "时区切换"
       echo "亚洲------------------------"
       echo "1. 中国上海时间              2. 中国香港时间"
       echo "3. 日本东京时间              4. 韩国首尔时间"
       echo "5. 新加坡时间                6. 印度加尔各答时间"
       echo "7. 阿联酋迪拜时间            8. 澳大利亚悉尼时间"
       echo "欧洲------------------------"
       echo "11. 英国伦敦时间             12. 法国巴黎时间"
       echo "13. 德国柏林时间             14. 俄罗斯莫斯科时间"
       echo "15. 荷兰尤特赖赫特时间       16. 西班牙马德里时间"
       echo "美洲------------------------"
       echo "21. 美国西部时间             22. 美国东部时间"
       echo "23. 加拿大时间               24. 墨西哥时间"
       echo "25. 巴西时间                 26. 阿根廷时间"
       echo "------------------------"
       echo "0. 返回上一级选单"
       echo "------------------------"
	   while true
       do
          read -p "请输入你的选择: " sub_choice
          case $sub_choice in
	         0)
               break 
                 ;;
             1)
               timedatectl set-timezone Asia/Shanghai
                 ;;
             2)
               timedatectl set-timezone Asia/Hong_Kong
                 ;;
             3)
               timedatectl set-timezone Asia/Tokyo
                 ;;
             4)
               timedatectl set-timezone Asia/Seoul
                 ;;
             5)
               timedatectl set-timezone Asia/Singapore
                 ;;
             6)
               timedatectl set-timezone Asia/Kolkata
                 ;;
             7)
               timedatectl set-timezone Asia/Dubai
                 ;;
             8)
               timedatectl set-timezone Australia/Sydney
                 ;;
             11)
               timedatectl set-timezone Europe/London
                 ;;
             12)
               timedatectl set-timezone Europe/Paris
                 ;;
             13)
               timedatectl set-timezone Europe/Berlin
                 ;;
             14)
               timedatectl set-timezone Europe/Moscow
                 ;;
             15)
               timedatectl set-timezone Europe/Amsterdam
                 ;;
             16)
               timedatectl set-timezone Europe/Madrid
                 ;;
             21)
               timedatectl set-timezone America/Los_Angeles
                 ;;
             22)
               timedatectl set-timezone America/New_York
                 ;;
             23)
               timedatectl set-timezone America/Vancouver
                 ;;
             24)
               timedatectl set-timezone America/Mexico_City
                 ;;
             25)
               timedatectl set-timezone America/Sao_Paulo
                 ;;
              26)
               timedatectl set-timezone America/Argentina/Buenos_Aires
                 ;;
               *)
               echo -e "$RED 请选择正确的操作！${PLAIN}"
            
                 ;;
          esac
	      get_time
	      echo "修改后系统时间信息"
	      echo -e "  ${GREEN}修改后系统时区：$current_timezone${PLAIN}"
	      echo -e "  ${GREEN}当前系统时间：$current_time${PLAIN}"
		  echo -e "  ${GREEN}已经修改完成，请输入0返回上一级菜单${PLAIN}"
        done
	 
	
}

man_htop(){
     htop

}

man_iftop(){
     iftop

}

man_disk(){

     ncdu
}


man_vnstat(){
  

			echo "可用的网络接口名称："
			echo -n -e  "${GREEN}可用的网络接口名称：${PLAIN}" && ifconfig -a | grep '^[a-zA-Z]' | awk '{print $1}' | tr '\n' ' ' | sed 's/://g'

			read -p "请输入你要监控的网络接口名称: " selected_interface

			echo " "
			echo "请选择操作模式："
			echo "0. 返回上一级菜单"
		    echo "1. 初始化网络接口：$selected_interface数据库"
			echo "2. 查看总体网络使用情况"
			echo "3. 查看每天的网络使用情况"
			echo "4. 查看每月的网络使用情况"
			echo "5. 删除网络接口：$selected_interface数据库"

	   while true
       do

			read -p "请输入你的选择: " choice
			case $choice in
			  0)
			     break
				 ;;
			  1)
			      if [ "$system_str" = "0" ]; then	         
			           vnstat --create -i $selected_interface
				  else
				       vnstat --add -i $selected_interface 
				  fi
				 ;;
			  2)
			
				vnstat
				;;
			  3)
			 
				vnstat -d
				;;
			  4)
			 
				vnstat -m
				;;
			  5)
			     if [ "$system_str" = "0" ]; then	         
			           vnstat --delete --force  -i $selected_interface
				  else
				      vnstat --remove  --force -i $selected_interface
				  fi
				;;
			  *)
				echo "无效的选择"
				;;
			esac

    done
}

disk_test(){
         curl -sL yabs.sh | bash -s -- -i -4
		 
}

netback_test(){
           wget -qO- git.io/besttrace | bash 
		
}  

speed_test(){
           bash <(curl -Lso- https://git.io/superspeed.sh)    
           		   
 
}

man_bbr() { 
        
		  bash <(curl -Lso- https://raw.githubusercontent.com/yirenchengfeng1/linux/main/bbr)

}

man_warp() {
      bash <(curl -fsSL git.io/warp.sh) menu

}

menu() {
    while true
    do
      clear
      echo    "#####################################################################################"
      echo -e "#                         ${RED}VPS日常管理一键脚本${PLAIN}                                         #"
	  echo -e "# ${GREEN}支持${PLAIN}: CentOS 7、Ubuntu、Debian                                                      #"
      echo -e "# ${GREEN}作者${PLAIN}: 爱分享的小企鹅                                                                #"
      echo -e "# ${GREEN}Youtube频道${PLAIN}: https://youtube.com/@user-wr7rz2jq4z?si=meznAMaijxYA9S2J               #"
      echo    "#####################################################################################"
	  echo -e "  ${GREEN}一、装机后操作${PLAIN}" 
	  echo -e "  ${GREEN}1.${PLAIN}  更新系统软件" 
	  echo -e "  ${GREEN}2.${PLAIN}  下载脚本执行依赖的命令"
      echo -e "  ${GREEN}3.${PLAIN}  修改系统时区"
	  echo -e "  ${GREEN}4.${PLAIN}  优化SSH的连接速度"
	  echo -e "  ${GREEN}5.${PLAIN}  更改SSH默认端口号"
	  echo -e "  ${GREEN}6.${PLAIN}  切换远程登录方式（密码or密钥）"
	  echo " -------------------"
	  echo -e "  ${GREEN}二、日常管理${PLAIN}" 
      echo -e "  ${GREEN}7.${PLAIN}  关机或重启系统"
	  echo -e "  ${GREEN}8.${PLAIN}  显示主机ip地址"
	  echo -e "  ${GREEN}9.${PLAIN}  管理系统防火墙"
	  echo " -------------------"
	  echo -e "  ${GREEN}三、服务器资源监控${PLAIN}"
      echo -e "  ${GREEN}10.${PLAIN}  实时CPU、内存等运行监控" 	 
      echo -e "  ${GREEN}11.${PLAIN}  磁盘使用情况监控"     	  
	  echo -e "  ${GREEN}12.${PLAIN}  实时网络流量监控"
      echo -e "  ${GREEN}13.${PLAIN}  历史网络流量查询"  
      echo " -------------------"	  
	  echo -e "  ${GREEN}四、服务器性能测试${PLAIN}"
      echo -e "  ${GREEN}14.${PLAIN}  显示系统信息以及CPU、内存、硬盘性能测试"  
	  echo -e "  ${GREEN}15.${PLAIN}  三网回程路由和延迟测试"  
	  echo -e "  ${GREEN}16.${PLAIN}  三网测试节点速度"  
	  echo " -------------------"
	  echo -e "  ${GREEN}五、开启额外功能${PLAIN}" 
	  echo -e "  ${GREEN}17.${PLAIN}  管理BBR"
	  echo -e "  ${GREEN}18.${PLAIN}  解锁chatgpt、Netflix..."
      echo " -------------"
      echo -e "  ${GREEN}0.${PLAIN} 退出"
      echo 
      read -p " 请选择操作[0-17]：" answer
      case $answer in
        0)
            exit 0
            ;;
		1)
            update_app
            ;;
        2)
            man_tools
            ;;		
        3)
            change_timezone
            ;;
        4)
            spead_ssh
            ;;
        5)
            man_ssh_port
            ;;
        6)
            ssh_login
            ;;
		7)
            powercontrol
            ;;
        8)
            dis_ip
            ;;	
			
        9)
            man_firewall
            ;;
        10)
            man_htop
            ;;
		11)
             man_disk
            ;;
        12)
            man_iftop
            ;;
        13)
            man_vnstat
            ;;
		14)
            disk_test
            ;;	
		15)
            netback_test
            ;;	
		16)
            speed_test
            ;;		
		17)
            man_bbr
            ;;		
        18)
            man_warp
            ;;			
        *)
            echo -e "$RED 请选择正确的操作！${PLAIN}"
            #exit 1
            ;;
      esac
	done
}

check_system

action=$1
[[ -z $1 ]] && action=menu
case "$action" in
    menu|update_app|man_tools|change_timezone|spead_ssh|man_ssh_port|ssh_login|powercontrol|dis_ip|man_firewall|man_htop|man_disk|man_iftop|man_vnstat|disk_test|netback_test|speed_test|man_bbr|man_warp)
        ${action}
        ;;
    *)
        echo " 参数错误"
        echo " 用法: `basename $0` [menu|update_app|man_tools|change_timezone|spead_ssh|man_ssh_port|ssh_login|powercontrol|dis_ip|man_firewall|man_htop|man_disk|man_iftop|man_vnstat|disk_test|netback_test|speed_test|man_bbr|man_warp]"
        ;;
esac

