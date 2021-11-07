import base64
import pyperclip


class Node_Remove_Repetition:
    def __init__(self):
        self.nodes_pool = []
        self.ip_pool = []
        self.new_nodes_pool = []
        self.is_json = False
        self.count_proxies = 0
    
    def read_txt(self):
        with open("./nodes_pool.txt", "r") as f:
            self.nodes_pool.append(f.readlines())
        self.count_proxies = self.nodes_pool[0].count('proxies:\n')     # 记录proxies出现次数
        for i in range(len(self.nodes_pool[0])):
            print('-' * 60)
            if self.nodes_pool[0][i].find('trojan://') != -1 or self.nodes_pool[0][i].find('vmess://') != -1 or self.nodes_pool[0][i].find('ss://') != -1 or self.nodes_pool[0][i].find('ssr://') != -1:
                self.is_json = False
                print('节点数量：{}个'.format(len(self.nodes_pool[0])))
                print('\t\t节点池格式：URL')
                break
            if self.nodes_pool[0][i].find('proxies') != -1 or self.nodes_pool[0][i].find('{') != -1 :
                self.is_json = True
                print('节点数量：{}个'.format(len(self.nodes_pool[0])-self.count_proxies), end='')
                print('\t\t节点池格式：json')
                break
    
    def extract_address(self):
        if self.is_json == False:           # 节点池若是URL格式，则执行
            for index, node in enumerate(self.nodes_pool[0]):
                if node.startswith('trojan://'):   # 提取trojan节点中的ip地址
                    trojan_decode = node.split(':', 2)[1].split('@')[1]
                    self.ip_pool.append(trojan_decode)
                if node.startswith('ss://'):       # 提取ss节点中的ip地址
                    ss_pad = len(node[5:])%4*'='
                    ss_decode = base64.b64decode(node.split('//', 2)[1].split('#')[0].replace('-', '+').replace('_', '/')+ss_pad).decode('utf-8', 'replace').split('@')[1].split(':')[0]
                    self.ip_pool.append(ss_decode)
                if node.startswith('ssr://'):
                    ssr_pad = len(node[6:])%4*'='
                    ssr_decode = base64.b64decode(node.split('//', 2)[1].replace('-', '+').replace('_', '/')+ssr_pad).decode('utf-8', 'replace').split(':')[0]
                    self.ip_pool.append(ssr_decode)
                if node.startswith('vmess://'):    # 提取vmess节点中的ip地址
                    vmess_pad = len(node[6:])%4*'='
                    vmess_decode = base64.b64decode(node.split('//', 2)[1]+vmess_pad).decode('utf-8', 'replace').split('"')
                    for vmess_index, vmess_value in enumerate(vmess_decode):
                        if vmess_value == 'add':
                            self.ip_pool.append(vmess_decode[vmess_index+2])
        if self.is_json == True:            # 节点池若是JSON格式，则执行
            true = ''   # eval()函数调用错误处理，将NameError变量赋值
            for i in range(len(self.nodes_pool[0])):
                if self.nodes_pool[0][i].find('proxies')+1:
                    self.ip_pool.append(self.nodes_pool[0][0])
                    continue
                self.ip_pool.append(eval(self.nodes_pool[0][i][2:])['server'])
    
    def save_nodes(self):
        nodes_copy_content = ''
        with open('./finish_nodes_pool.txt', 'w') as f:
            for ip_index, ip in enumerate(self.ip_pool):
                if ip_index == self.ip_pool.index(ip):
                    self.new_nodes_pool.append(self.nodes_pool[0][ip_index])
                    f.write(self.nodes_pool[0][ip_index])
                    nodes_copy_content += self.nodes_pool[0][ip_index]
        pyperclip.copy(nodes_copy_content)
    
    def view_result(self):
        remove_ip_length = len(self.ip_pool) - len(self.new_nodes_pool)
        print('-' * 60)
        if self.is_json == True:
            print('删除重复节点：{}个\t\t剩余节点：{}个'.format(remove_ip_length-self.count_proxies+1, len(self.new_nodes_pool)-1))
        if self.is_json == False:
            print('删除重复节点：{}个\t\t剩余节点：{}个'.format(remove_ip_length, len(self.new_nodes_pool)))
        print('-' * 60)
        print('已将节点信息复制到剪贴板。\t按回车键退出')
        print('=' * 60)
        exit_wait = input('')
    
    def run(self):
        """ 1.读取TXT中的节点数据，判断节点池格式 """
        self.read_txt()
        """ 2.提取节点中的IP地址 """
        self.extract_address()
        """ 3.IP地址去重，结果保存到TXT """
        self.save_nodes()
        """ 4.显示去重结果 """
        self.view_result()


if __name__ == "__main__":
    nodes_sifter = Node_Remove_Repetition()
    nodes_sifter.run()
