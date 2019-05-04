import sys
import json
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
 
def init_matrix():
    tactics = {}

    # 读取Tactics字典
    with open('Tactics.json', 'r', encoding='utf-8') as json_file:
        tactics = json.load(json_file)

    tmp_tac_tech = []
    max_tech_num = 0
    tact_num = 0

    for tact in tactics['Enterprise']:
        tact_num += 1

        tmp = []
        tmp.append(tact)

        if len(tactics['Enterprise'][tact]['Techniques']) > max_tech_num:
            max_tech_num = len(tactics['Enterprise'][tact]['Techniques'])

        for tech in tactics['Enterprise'][tact]['Techniques']:
            tmp.append(tech['Name'])

        tmp_tac_tech.append(tmp)

    tac_tech = [''] * ((max_tech_num + 1) * tact_num)

    for i in range(0, len(tmp_tac_tech)):
        for j in range(0, len(tmp_tac_tech[i])):
            tac_tech[(j * tact_num) + i] = tmp_tac_tech[i][j]

    return tac_tech


class MatrixButton(QPushButton):
    def __init__(self, parent=None, main_window=None):
        QPushButton.__init__(self, parent)
        self.name = ""
        self.tac_name = ""
        self.tac0_tech1 = None
        self.main_window = main_window
        self.clicked.connect(self.click_action)

    def click_action(self):
        if self.tac0_tech1 == 0:
            # print(self.name)
            self.main_window.create_tac_tab(self.name)
        else:
            # print(self.name)
            self.main_window.create_tech_tab(self.name, self.tac_name)
        # self.main_window.setWindowTitle("ATT&CK 2")


class MainWindow(QTabWidget):
    def __init__(self,parent=None):
        super(MainWindow, self).__init__(parent)

        self.tactics = []
        self.techniques = []
        self.softwares = []
        self.groups = []

        # 读取Tactics字典
        with open('Tactics.json', 'r', encoding='utf-8') as json_file:
            self.tactics = json.load(json_file)

        # 读取Techniques字典
        with open('Techniques.json', 'r', encoding='utf-8') as json_file:
            self.techniques = json.load(json_file)

        # 读取Software字典
        with open('Software.json', 'r', encoding='utf-8') as json_file:
            self.softwares = json.load(json_file)

        # 读取Groups字典
        with open('Groups.json', 'r', encoding='utf-8') as json_file:
            self.groups = json.load(json_file)

        # Tactics-Techniques Detected Events, MapButtons, Detected Table

        self.tac_tech_events = {}
        for elem in self.tactics['Enterprise']:
            self.tac_tech_events[elem] = {}
            self.tac_tech_events[elem]['Table'] = self.make_detected_table()
            self.tac_tech_events[elem]['Events'] = []
            for elem2 in self.tactics['Enterprise'][elem]['Techniques']:
                self.tac_tech_events[elem][elem2['Name']] = {}
                self.tac_tech_events[elem][elem2['Name']]['Events'] = []
                self.tac_tech_events[elem][elem2['Name']]['Table'] = self.make_detected_table()

        self.setMinimumSize(1530,900)
        self.setMaximumSize(1530,900)

        # 添加关闭Tab功能
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self.close_tab)

        self.tab1=QWidget()
        self.tab2=QWidget()

        self.make_matrix()

        self.addTab(self.tab1, "Tab 1")
        self.addTab(self.tab2, "ATT&CK Matrix")

        self.tab1UI()
        self.tab2UI()

        self.setWindowTitle("ATT&CK")

    def make_detected_table(self):
        table = QTableWidget(4,3)
        # 点击事件
        #self.tac_detected.itemClicked.connect(self.tac_item_clicked)
        # 去掉边框线
        table.setFrameShape(QFrame.NoFrame);
        # 设置表格整行选中
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # 设置垂直方向的表头标签
        table.setHorizontalHeaderLabels(['Time', 'CAR-ID', 'CAR-NAME'])
        # 设置水平方向表格为自适应的伸缩模式
        #self.tac_detected.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 将表格变为禁止编辑
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 表格头的显示与隐藏
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

        return table

    def make_matrix(self):
        topFiller = QWidget()
        topFiller.setMinimumSize(1530, 3200)#######设置滚动条的尺寸

        tac_tech = init_matrix()
        tac_tech_width = 11
        tac_tech_height = 64

        count = 0
        button_width = 135
        button_height = 50

        # ATT&CK 매트리스 버튼 만들기

        for tactech in tac_tech:
            if tactech == '':
                count += 1
                continue

            MapButton = MatrixButton(topFiller, self)
            MapButton.name = tactech
            MapButton.resize(button_width, button_height)

            # 띄어쓰기... 텍스트가 너무 길면 버튼 밖으로 나가서 안보임..
            enter_count = 0
            newstr = ""
            for ch in tactech:
                if ch == ' ':
                    if enter_count % 2 == 1:
                        newstr += '\n'
                    else:
                        newstr += ' '
                    enter_count += 1
                else:
                    newstr += ch

            MapButton.setText(newstr)
            MapButton.move(button_width * (count%11),button_height * int(count/11))

            # Tactics 매트릭스 원소 색깔 바꿔서 차이점 주기!
            if int(count/11) > 0:
                # Technique
                MapButton.setStyleSheet('font:10px;'
                    'text-align : center;' 
                    'padding: 0px;'
                    'background-color: rgb(252, 252, 252);'
                    'border-style: outset;'
                    'border-width: 1px;'
                    'border-color: rgb(220, 220, 220);')
                # MapButton.setToolTip("Description")
                MapButton.tac0_tech1 = 1
                MapButton.tac_name = tac_tech[count % 11]
                self.tac_tech_events[tac_tech[count % 11]][tactech]['Button'] = MapButton
            else:
                #Tactics
                MapButton.setStyleSheet('font:11px;'
                    'text-align : center;' 
                    'padding: 0px;'
                    'background-color: rgb(80, 80, 80);'
                    'color: rgb(252, 252, 252);'
                    'font-weight: bold;')
                MapButton.tac0_tech1 = 0
                self.tac_tech_events[tactech]['Button'] = MapButton

            count += 1

            # MapButton.clicked.connect(lambda:self.tech_clicked(MapButton.text()))

        ##创建一个滚动条
        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)
 
        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        self.tab2.setLayout(vbox)


    def tab1UI(self):
        #表单布局
        layout=QFormLayout()
        #添加姓名，地址的单行文本输入框
        layout.addRow('A',QLabel())
        layout.addRow('地址',QLineEdit())
        #设置选项卡的小标题与布局方式
        self.setTabText(0,'联系方式')
        self.tab1.setLayout(layout)

    def tab2UI(self):
        print('2')

    #关闭tab
    def close_tab(self, index):
        if self.count()>1 and index != 0 and index != 1:
            self.removeTab(index)
        elif index == 0 or index == 1:
            # TODO
            print('No')
        else:
            # TODO
            self.close()   # 当只有1个tab时，关闭主窗口

    #创建tactics tab
    def create_tac_tab(self, name):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        for key in self.tactics['Enterprise'][name]:
            if type(self.tactics['Enterprise'][name][key]) != type([]):
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'padding: 0px;'
                    'font-weight: bold;')

                # newstr = key + ' : ' + self.tactics['Enterprise'][name][key]
                # print(newstr)
                layout.addRow(key_label,QLabel())
                row_count += 3

                descript_str = self.tactics['Enterprise'][name][key]

                while 1:
                    if len(descript_str) > 150:
                        tmp_str = descript_str[:150]
                        while 1:
                            if tmp_str[-1] == ' ':
                                break
                            else:
                                tmp_str = tmp_str[:-1]

                        descript_str = descript_str[len(tmp_str):]

                        descript_label = QLabel('   ' + tmp_str)
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                    else:
                        descript_label = QLabel('   ' + descript_str + '\n')
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                        break

            else:
                
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
                layout.addRow(key_label,QLabel())

                column_count = 0
                column_list = []
                for list_elem in self.tactics['Enterprise'][name][key]:
                    for list_key in list_elem:
                        column_list.append(list_key)
                        column_count += 1
                    break

                table_widget = QTableWidget(10,column_count)
                table_widget.name = name
                table_widget.itemClicked.connect(self.tac_item_clicked)
                # 设置表头不可点击
                # table_widget.horizontalHeader().setClickable(False);
                # 去掉边框线
                table_widget.setFrameShape(QFrame.NoFrame);
                # 设置表格整行选中
                table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
                # 设置垂直方向的表头标签
                table_widget.setHorizontalHeaderLabels(column_list)
                # 设置水平方向表格为自适应的伸缩模式
                #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                # 将表格变为禁止编辑
                table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                # 表格头的显示与隐藏
                table_widget.verticalHeader().setVisible(False)
                table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

                row_num = 0
                row_index = 0
                for list_elem in self.tactics['Enterprise'][name][key]:
                    column_index = 0
                    row_index += 1
                    for list_key in list_elem:
                        table_widget.setRowCount(row_index)

                        item_text = list_elem[list_key]
                        tmp_text_list = []
                        while 1:
                            if len(item_text) > 130:
                                tmp_str = item_text[:130]
                                while 1:
                                    if tmp_str[-1] == ' ':
                                        break
                                    else:
                                        tmp_str = tmp_str[:-1]

                                item_text = item_text[len(tmp_str):]

                                tmp_text_list.append(tmp_str + '\n')
                                row_count += 1.3
                            else:
                                tmp_text_list.append(item_text)
                                row_count += 1.3
                                break

                        item_text = ""
                        for elem in tmp_text_list:
                            item_text += elem

                        new_item=QTableWidgetItem(item_text)
                        new_item.setFont(QFont('Times New Roman',13))
                        # new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index - 1, column_index, new_item)

                        column_index += 1
                        row_num += 1


                QTableWidget.resizeColumnsToContents(table_widget)
                QTableWidget.resizeRowsToContents(table_widget)
                row_num += 2 # HorisonHeader
                table_widget.setMinimumSize(1400,row_num * 13)
                layout.addRow(table_widget,QLabel())

        # Detected Event
        key_label = QLabel('\nDetected Event')
        key_label.setStyleSheet('font:30px;'
            #'font-family : Times New Roman'
            'text-align : center;' 
            'padding: 0px;'
            'font-weight: bold;')
        layout.addRow(key_label,QLabel())

        QTableWidget.resizeColumnsToContents(self.tac_tech_events[name]['Table'])
        QTableWidget.resizeRowsToContents(self.tac_tech_events[name]['Table'])
        self.tac_tech_events[name]['Table'].setMinimumSize(1400,200)
        layout.addRow(self.tac_tech_events[name]['Table'],QLabel())
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'Tactics - ' + name)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    #创建techniques tab
    def create_tech_tab(self, name, tact=None):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        for key in self.techniques['Enterprise'][name]:
            if type(self.techniques['Enterprise'][name][key]) != type([]):
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'padding: 0px;'
                    'font-weight: bold;')

                layout.addRow(key_label,QLabel())
                row_count += 3

                descript_str = self.techniques['Enterprise'][name][key]

                while 1:
                    if len(descript_str) > 150:
                        tmp_str = descript_str[:150]
                        while 1:
                            if tmp_str[-1] == ' ':
                                break
                            else:
                                tmp_str = tmp_str[:-1]

                        descript_str = descript_str[len(tmp_str):]

                        descript_label = QLabel('   ' + tmp_str)
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                    else:
                        descript_label = QLabel('   ' + descript_str + '\n')
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                        break

            else:
                
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
                layout.addRow(key_label,QLabel())

                column_count = 0
                column_list = []
                for list_elem in self.techniques['Enterprise'][name][key]:
                    for list_key in list_elem:
                        column_list.append(list_key)
                        column_count += 1
                    break

                table_widget = QTableWidget(10,column_count)
                table_widget.itemClicked.connect(self.tech_item_clicked)
                # 去掉边框线
                table_widget.setFrameShape(QFrame.NoFrame);
                # 设置表格整行选中
                table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
                # 设置垂直方向的表头标签
                table_widget.setHorizontalHeaderLabels(column_list)
                # 设置水平方向表格为自适应的伸缩模式
                #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                # 将表格变为禁止编辑
                table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                # 表格头的显示与隐藏
                table_widget.verticalHeader().setVisible(False)
                table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

                row_num = 0
                row_index = 0
                for list_elem in self.techniques['Enterprise'][name][key]:
                    column_index = 0
                    row_index += 1
                    for list_key in list_elem:
                        table_widget.setRowCount(row_index)

                        item_text = list_elem[list_key]
                        tmp_text_list = []
                        while 1:
                            if len(item_text) > 130:
                                tmp_str = item_text[:130]
                                while 1:
                                    if tmp_str[-1] == ' ':
                                        break
                                    else:
                                        tmp_str = tmp_str[:-1]

                                item_text = item_text[len(tmp_str):]

                                tmp_text_list.append(tmp_str + '\n')
                                row_count += 1.3
                            else:
                                tmp_text_list.append(item_text)
                                row_count += 1.3
                                break

                        item_text = ""
                        for elem in tmp_text_list:
                            item_text += elem

                        new_item=QTableWidgetItem(item_text)
                        new_item.setFont(QFont('Times New Roman',13))
                        # new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index - 1, column_index, new_item)

                        column_index += 1
                        row_num += 1


                QTableWidget.resizeColumnsToContents(table_widget)
                QTableWidget.resizeRowsToContents(table_widget)
                row_num += 2 # HorisonHeader
                table_widget.setMinimumSize(1400,row_num * 13)
                layout.addRow(table_widget,QLabel())

        # Detected Event
        key_label = QLabel('\nDetected Event')
        key_label.setStyleSheet('font:30px;'
            #'font-family : Times New Roman'
            'text-align : center;' 
            'padding: 0px;'
            'font-weight: bold;')
        layout.addRow(key_label,QLabel())

        tac_name = ''
        if tact != None:
            tac_name = tact
        else:
            tac_name = self.techniques['Enterprise'][name]['Tactic']
            if ',' in tac_name:
                tac_name = tac_name.split(',')[0]

        QTableWidget.resizeColumnsToContents(self.tac_tech_events[tac_name][name]['Table'])
        QTableWidget.resizeRowsToContents(self.tac_tech_events[tac_name][name]['Table'])
        self.tac_tech_events[tac_name][name]['Table'].setMinimumSize(1400,200)
        layout.addRow(self.tac_tech_events[tac_name][name]['Table'],QLabel())
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'Techniques - ' + name)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    #创建Groups tab
    def create_group_tab(self, name):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        for key in self.groups[name]:
            if type(self.groups[name][key]) != type([]):
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'padding: 0px;'
                    'font-weight: bold;')

                layout.addRow(key_label,QLabel())
                row_count += 3

                descript_str = self.groups[name][key]

                while 1:
                    if len(descript_str) > 150:
                        tmp_str = descript_str[:150]
                        while 1:
                            if tmp_str[-1] == ' ':
                                break
                            else:
                                tmp_str = tmp_str[:-1]

                        descript_str = descript_str[len(tmp_str):]

                        descript_label = QLabel('   ' + tmp_str)
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                    else:
                        descript_label = QLabel('   ' + descript_str + '\n')
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                        break

            else:
                
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
                layout.addRow(key_label,QLabel())

                column_count = 0
                column_list = []
                for list_elem in self.groups[name][key]:
                    for list_key in list_elem:
                        column_list.append(list_key)
                        column_count += 1
                    break

                table_widget = QTableWidget(10,column_count)
                table_widget.itemClicked.connect(self.group_item_clicked)
                # 去掉边框线
                table_widget.setFrameShape(QFrame.NoFrame);
                # 设置表格整行选中
                table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
                # 设置垂直方向的表头标签
                table_widget.setHorizontalHeaderLabels(column_list)
                # 设置水平方向表格为自适应的伸缩模式
                #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                # 将表格变为禁止编辑
                table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                # 表格头的显示与隐藏
                table_widget.verticalHeader().setVisible(False)
                table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

                row_num = 0
                row_index = 0
                for list_elem in self.groups[name][key]:
                    column_index = 0
                    row_index += 1
                    for list_key in list_elem:
                        table_widget.setRowCount(row_index)

                        item_text = list_elem[list_key]
                        tmp_text_list = []
                        while 1:
                            if len(item_text) > 130:
                                tmp_str = item_text[:130]
                                while 1:
                                    if tmp_str[-1] == ' ':
                                        break
                                    else:
                                        tmp_str = tmp_str[:-1]

                                item_text = item_text[len(tmp_str):]

                                tmp_text_list.append(tmp_str + '\n')
                                row_count += 1.3
                            else:
                                tmp_text_list.append(item_text)
                                row_count += 1.3
                                break

                        item_text = ""
                        for elem in tmp_text_list:
                            item_text += elem

                        new_item=QTableWidgetItem(item_text)
                        new_item.setFont(QFont('Times New Roman',13))
                        # new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index - 1, column_index, new_item)

                        column_index += 1
                        row_num += 1


                QTableWidget.resizeColumnsToContents(table_widget)
                QTableWidget.resizeRowsToContents(table_widget)
                row_num += 2 # HorisonHeader
                table_widget.setMinimumSize(1400,row_num * 13)
                layout.addRow(table_widget,QLabel())

        # Detected Event
        key_label = QLabel('\nDetected Event')
        key_label.setStyleSheet('font:30px;'
            #'font-family : Times New Roman'
            'text-align : center;' 
            'padding: 0px;'
            'font-weight: bold;')
        layout.addRow(key_label,QLabel())

        QTableWidget.resizeColumnsToContents(table_widget)
        QTableWidget.resizeRowsToContents(table_widget)
        # self.group_detected.setMinimumSize(1400,200)
        # layout.addRow(self.group_detected,QLabel())
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'Groups - ' + name)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    #创建Softwares tab
    def create_sw_tab(self, name):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        for key in self.softwares[name]:
            if type(self.softwares[name][key]) != type([]):
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'padding: 0px;'
                    'font-weight: bold;')

                layout.addRow(key_label,QLabel())
                row_count += 3

                descript_str = self.softwares[name][key]

                while 1:
                    if len(descript_str) > 150:
                        tmp_str = descript_str[:150]
                        while 1:
                            if tmp_str[-1] == ' ':
                                break
                            else:
                                tmp_str = tmp_str[:-1]

                        descript_str = descript_str[len(tmp_str):]

                        descript_label = QLabel('   ' + tmp_str)
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                    else:
                        descript_label = QLabel('   ' + descript_str + '\n')
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                        break

            else:
                
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
                layout.addRow(key_label,QLabel())

                column_count = 0
                column_list = []
                for list_elem in self.softwares[name][key]:
                    if type(list_elem) == type(""):
                        column_count = 1
                        column_list = ['Name']
                    else:
                        for list_key in list_elem:
                            column_list.append(list_key)
                            column_count += 1
                    break

                table_widget = QTableWidget(1,column_count)
                table_widget.itemClicked.connect(self.sw_item_clicked)
                # 去掉边框线
                table_widget.setFrameShape(QFrame.NoFrame);
                # 设置表格整行选中
                table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
                # 设置垂直方向的表头标签
                table_widget.setHorizontalHeaderLabels(column_list)
                # 设置水平方向表格为自适应的伸缩模式
                #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                # 将表格变为禁止编辑
                table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                # 表格头的显示与隐藏
                table_widget.verticalHeader().setVisible(False)
                table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

                row_num = 0
                row_index = 0
                for list_elem in self.softwares[name][key]:
                    column_index = 0
                    row_index += 1
                    if type(list_elem) == type(""):
                        new_item=QTableWidgetItem(list_elem)
                        new_item.setFont(QFont('Times New Roman',13))
                        new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index - 1, column_index, new_item)
                        row_count += 1.3
                    else:
                        for list_key in list_elem:
                            table_widget.setRowCount(row_index)

                            item_text = list_elem[list_key]
                            tmp_text_list = []
                            while 1:
                                if len(item_text) > 130:
                                    tmp_str = item_text[:130]
                                    while 1:
                                        if tmp_str[-1] == ' ':
                                            break
                                        else:
                                            tmp_str = tmp_str[:-1]

                                    item_text = item_text[len(tmp_str):]

                                    tmp_text_list.append(tmp_str + '\n')
                                    row_count += 1.3
                                else:
                                    tmp_text_list.append(item_text)
                                    row_count += 1.3
                                    break

                            item_text = ""
                            for elem in tmp_text_list:
                                item_text += elem

                            new_item=QTableWidgetItem(item_text)
                            new_item.setFont(QFont('Times New Roman',13))
                            table_widget.setItem(row_index - 1, column_index, new_item)

                            column_index += 1
                            row_num += 1


                QTableWidget.resizeColumnsToContents(table_widget)
                QTableWidget.resizeRowsToContents(table_widget)
                row_num += 2 # HorisonHeader
                table_widget.setMinimumSize(1400,row_num * 13)
                layout.addRow(table_widget,QLabel())
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'softwares - ' + name)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    def tac_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        tec_name = parent.item(item.row(), 1).text()
        self.create_tech_tab(tec_name, parent.name)

    def tech_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        name = parent.item(item.row(), 0).text()
        try:
            self.create_group_tab(name)
        except:
            self.create_sw_tab(name)

    def group_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        if parent.columnCount() == 4:
            name = parent.item(item.row(), 2).text()
            self.create_tech_tab(name)
        else:
            name = parent.item(item.row(), 1).text()
            self.create_sw_tab(name)

    def sw_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        
        if parent.columnCount() == 4:
            name = parent.item(item.row(), 2).text()
            self.create_tech_tab(name)
        else:
            name = parent.item(item.row(), 0).text()
            self.create_group_tab(name)
            


 
if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainwindow = MainWindow()
    mainwindow.show()
    sys.exit(app.exec_())