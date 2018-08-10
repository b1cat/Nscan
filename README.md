# Nscan
端口扫描小脚本，支持批量任意端口开放探测，Web端口title抓取，线程池线程控制等

## 依赖模块安装
` pip3 install IPy`

## 设计流程
1. 解析参数
2. 根据socket连接返回值，判断是否开放
3. 若为Web服务，抓取HTTP title
4. 输出结果到指定文件

## 重要的
欢迎提交Issue ~
