import base64


class Node_Remove_Repetition:
    def __init__(self):
        self.nodes_pool = []
        self.ip_pool = []
        self.new_nodes_pool = []
    
    def read_txt(self):
        with open("./nodes_pool.txt", "r") as f:
            self.nodes_pool.append(f.readlines())
    
    def extract_address(self):
        for index, node in enumerate(self.nodes_pool[0]):
            node_type = node.split(':', 1)[0]
            if node_type == 'trojan':   # 使用字符串方法提取trojan节点中的ip地址
                trojan_decode = node.split(':', 2)[1].split('@')[1]
                self.ip_pool.append(trojan_decode)
            if node_type == 'ss':       # 先解码，再使用字符串方法提取ss节点中的ip地址
                ss_decode = base64.b64decode(node.split('//', 2)[1].split('#')[0]).decode('utf-8','replace').split('@')[1].split(':')[0]
                self.ip_pool.append(ss_decode)
            if node_type == 'vmess':    # 先解码，再使用字符串方法提取vmess节点中的ip地址
                vmess_decode = base64.b64decode(node.split('//', 2)[1]+'=').decode('utf-8','replace').split('"')
                for vmess_index, vmess_value in enumerate(vmess_decode):
                    if vmess_value == 'add':
                        self.ip_pool.append(vmess_decode[vmess_index+2])
    
    def save_nodes(self):
        with open('./finish_nodes_pool.txt', 'w') as f:
            for ip_index, ip in enumerate(self.ip_pool):
                if ip_index == self.ip_pool.index(ip):
                    self.new_nodes_pool.append(self.nodes_pool[0][ip_index])
                    f.write(self.nodes_pool[0][ip_index])
    
    def view_result(self):
        remove_ip_length = len(self.ip_pool) - len(self.new_nodes_pool)
        print('删除重复节点：{}个，剩余节点：{}个'.format(remove_ip_length, len(self.new_nodes_pool)))
    
    def run(self):
        """ 1.读取TXT中的节点数据 """
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