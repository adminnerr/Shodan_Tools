import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, Toplevel
import shodan
import threading

# Shodan API Key
API_KEY = "AmnP4zrAoawggLagxymD3sexTUYyOKUy"
api = shodan.Shodan(API_KEY)


# 批量检测功能（多线程处理，并在完成后弹窗提示）
def batch_scan():
    file_path = filedialog.askopenfilename(title="选择要批量检测的txt文件", filetypes=[("Text Files", "*.txt")])

    if not file_path:
        text_box.insert(tk.END, "未选择文件\n")
        return

    text_box.insert(tk.END, f"已选择文件: {file_path}\n")

    event = threading.Event()

    def scan_ip(ip, remaining_ips):
        try:
            host = api.host(ip)
            has_vuln = bool(host.get("vulns"))
            honeypot = host.get("honeypot", False)

            print("Host data:", host)

            if has_vuln:
                # 获取 CVE 名称，如果有漏洞
                if isinstance(host.get("vulns"), dict):
                    vulns = ", ".join(host["vulns"].keys())
                else:
                    vulns = "未知漏洞格式"

                result = f"{ip}: 有漏洞 ({vulns}) - {'有蜜罐' if honeypot else '无蜜罐'}\n"
            else:
                result = f"{ip}: 无漏洞 - {'有蜜罐' if honeypot else '无蜜罐'}\n"

            text_box.insert(tk.END, result)
        except shodan.APIError as e:
            text_box.insert(tk.END, f"{ip}: Shodan API 请求失败 - {str(e)}\n")
        finally:
            remaining_ips[0] -= 1
            if remaining_ips[0] == 0:
                event.set()

    with open(file_path, "r") as file:
        ips = [ip.strip() for ip in file.readlines() if ip.strip()]
        remaining_ips = [len(ips)]
        threads = []
        for ip in ips:
            thread = threading.Thread(target=scan_ip, args=(ip, remaining_ips))
            thread.start()
            threads.append(thread)

    def check_done():
        for thread in threads:
            thread.join()
        messagebox.showinfo("检测完成", "所有IP检测完毕！")

    threading.Thread(target=check_done).start()





# 查询单个IP信息功能（多线程处理）
def check_single_ip(ip, output_box):
    def scan_ip():
        try:
            host = api.host(ip)
            output_box.insert(tk.END, f"IP: {ip}\n")

            country = host.get("country_name", "未知")
            region = host.get("region_name", "未知")
            os_info = host.get("os", "未知")
            honeypot = "是" if host.get("honeypot", False) else "否"

            output_box.insert(tk.END, f"国家: {country}\n地区: {region}\n操作系统: {os_info}\n蜜罐: {honeypot}\n")

            output_box.insert(tk.END, "开放端口:\n")
            for item in host['data']:
                port = item['port']
                product = item.get('product', '未知服务')
                output_box.insert(tk.END, f"Port: {port} ({product})\n")

            if 'vulns' in host:
                output_box.insert(tk.END, "漏洞:\n")
                for vuln in host['vulns']:
                    output_box.insert(tk.END, f"漏洞: {vuln}\n")
            else:
                output_box.insert(tk.END, "无漏洞\n")

            for item in host.get('data', []):
                if 'http' in item:
                    status_code = item['http'].get('status', '无状态码')
                    title = item['http'].get('title', '无标题')
                    output_box.insert(tk.END, f"网页标题: {title}\n状态码: {status_code}\n")

        except shodan.APIError as e:
            output_box.insert(tk.END, f"Shodan API 请求失败: {str(e)}\n")

    threading.Thread(target=scan_ip).start()


# 打开单个IP检测窗口
def open_single_ip_window():
    new_window = Toplevel(window)
    new_window.title("单个IP漏洞和端口检测")

    ip_label = tk.Label(new_window, text="输入IP地址:")
    ip_label.grid(row=0, column=0, padx=10, pady=10)

    ip_entry = tk.Entry(new_window, width=30)
    ip_entry.grid(row=0, column=1, padx=10, pady=10)

    output_box = scrolledtext.ScrolledText(new_window, width=60, height=20)
    output_box.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

    check_button = tk.Button(new_window, text="查询漏洞和端口",
                             command=lambda: check_single_ip(ip_entry.get(), output_box))
    check_button.grid(row=0, column=2, padx=10, pady=10)


# 打开Shodan搜索窗口
def open_search_window():
    search_window = Toplevel(window)
    search_window.title("Shodan搜索")

    search_label = tk.Label(search_window, text="搜索内容:")
    search_label.grid(row=0, column=0, padx=10, pady=10)

    search_entry = tk.Entry(search_window, width=30)
    search_entry.grid(row=0, column=1, padx=10, pady=10)

    count_label = tk.Label(search_window, text="查询数量:")
    count_label.grid(row=1, column=0, padx=10, pady=10)

    count_entry = tk.Entry(search_window, width=30)
    count_entry.grid(row=1, column=1, padx=10, pady=10)

    output_box = scrolledtext.ScrolledText(search_window, width=60, height=20)
    output_box.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def search_shodan():
        query = search_entry.get()
        count = int(count_entry.get())

        def perform_search():
            try:
                results = api.search(query, limit=count)
                output_box.insert(tk.END, f"查询 '{query}' 的结果:\n")
                for result in results['matches']:
                    ip_str = f"IP: {result['ip_str']}, 端口: {result.get('port', '未知')}\n"
                    output_box.insert(tk.END, ip_str)
            except shodan.APIError as e:
                output_box.insert(tk.END, f"Shodan API 请求失败: {str(e)}\n")

        threading.Thread(target=perform_search).start()

    search_button = tk.Button(search_window, text="确定", command=search_shodan)
    search_button.grid(row=0, column=2, padx=10, pady=10)


def new_batch_scan():
    file_path = filedialog.askopenfilename(title="选择要批量检测的txt文件", filetypes=[("Text Files", "*.txt")])

    if not file_path:
        text_box.insert(tk.END, "未选择文件\n")
        return

    text_box.insert(tk.END, f"已选择文件: {file_path}\n")

    event = threading.Event()

    def scan_ip(ip, remaining_ips):
        try:
            host = api.host(ip)
            has_vuln = host.get("vulns", False)
            honeypot = host.get("honeypot", False)
            status_code = host.get('http', {}).get('status', '无状态码')

            if has_vuln:
                vulns = ", ".join(host["vulns"])
                result = f"{ip}: {vulns} - 状态码: {status_code} - {'有蜜罐' if honeypot else '无蜜罐'}\n"
            else:
                result = f"{ip}: 无漏洞 - 状态码: {status_code} - {'有蜜罐' if honeypot else '无蜜罐'}\n"

            text_box.insert(tk.END, result)
        except shodan.APIError as e:
            text_box.insert(tk.END, f"{ip}: Shodan API 请求失败 - {str(e)}\n")
        finally:
            remaining_ips[0] -= 1
            if remaining_ips[0] == 0:
                event.set()

    with open(file_path, "r") as file:
        ips = [ip.strip() for ip in file.readlines()]
        remaining_ips = [len(ips)]
        for ip in ips:
            threading.Thread(target=scan_ip, args=(ip, remaining_ips)).start()

    def check_done():
        event.wait()
        messagebox.showinfo("检测完成", "所有IP检测完毕！")

    threading.Thread(target=check_done).start()



# 创建GUI窗口
window = tk.Tk()
window.title("Shodan Tools     by kai_kk")

scan_button = tk.Button(window, text="批量检测是否有cve漏洞", command=batch_scan)
scan_button.grid(row=0, column=0, padx=10, pady=10)

single_ip_button = tk.Button(window, text="单个IP检测", command=open_single_ip_window)
single_ip_button.grid(row=0, column=1, padx=10, pady=10)

search_button = tk.Button(window, text="Shodan搜索", command=open_search_window)
search_button.grid(row=0, column=2, padx=10, pady=10)

search_button = tk.Button(window, text="批量检测2.0", command=new_batch_scan)
search_button.grid(row=0, column=3, padx=10, pady=10)

text_box = scrolledtext.ScrolledText(window, width=80, height=20)
text_box.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

window.mainloop()

'''
1.先用 shodan search --limit 100 country:jp    找资产IP
2.   用这个工具找，那个IP有漏洞
3.找poc试试
'''