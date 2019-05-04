#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket
import time
import requests #导入requests 模块
from bs4 import BeautifulSoup  #导入BeautifulSoup 模块
import re
import json
from pathlib import Path

def get_real_text(text):
    newstr = text
    while 1:
        if newstr[0] in ['\n', ' ', ' ', '\t', ':']:
            newstr = newstr[1:]
        else:
            break
    while 1:
        if newstr[-1] in ['\n', ' ', ' ', '\t', ':']:
            newstr = newstr[:-1]
        else:
            break
    return newstr

def get_html_label(web_url):
    timeout = 20
    socket.setdefaulttimeout(timeout)
    #sleep_download_time = 1
    #time.sleep(sleep_download_time)
    # 给请求指定一个请求头来模拟chrome浏览器
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'}
    # 像目标url地址发送get请求，返回一个response对象
    req = requests.get(web_url, headers=headers)
    req.encoding = 'utf-8'

    html_label = BeautifulSoup(req.text, 'lxml')
    req.close()
    return html_label


def group_get_page_content(url, group_name):
    result_dict = {}

    labels = get_html_label(url)
    container = labels.find('div', id='v-attckmatrix')

    result_dict['Name'] = group_name
    result_dict['Description'] = get_real_text(container.find('div', class_='col-md-8 description-body').text)
    attr_card_bodys = container.find_all('div', class_='card-data')

    for elem in attr_card_bodys:
        span_label = elem.find('span')
        attr_name = span_label.text
        span_label.extract()

        attr_value = get_real_text(elem.text)

        result_dict[attr_name] = attr_value

    tables = container.find_all('table', class_='table table-bordered table-light mt-2')
    for elem in tables:
        thead = elem.find('thead')
        ths = thead.find_all('th')
        tmp_ths = []
        for th in ths:
            tmp_ths.append(th.text)
        ths = tmp_ths

        tbody = elem.find('tbody', class_='bg-white')

        if 'Domain' in thead.text:
            # print('Techniques Used')
            tech = []
            trs = tbody.find_all('tr')
            for tr in trs:
                tds = tr.find_all('td')
                idx = 0
                tech_elem = {}
                for td in tds:
                    tech_elem[ths[idx]] = td.text
                    idx += 1
                tech.append(tech_elem)
            result_dict['Techniques Used'] = tech

        elif 'Techniques' in thead.text:
            # print('Software')
            sw = []
            trs = tbody.find_all('tr')
            for tr in trs:
                tds = tr.find_all('td')
                idx = 0
                sw_elem = {}
                for td in tds:
                    sw_elem[ths[idx]] = td.text
                    idx += 1
                sw.append(sw_elem)
            result_dict['Software'] = sw

    return result_dict


def tech_get_page_content(url, tech_name):
    result_dict = {}

    labels = get_html_label(url)
    container = labels.find('div', id='v-attckmatrix')

    result_dict['Name'] = tech_name
    result_dict['Description'] = get_real_text(container.find('div', class_='col-md-8 description-body').text)
    attr_card_bodys = container.find_all('div', class_='card-data')

    for elem in attr_card_bodys:
        span_label = elem.find('span')
        attr_name = span_label.text

        if attr_name != "":
            span_label.extract()
            attr_value = get_real_text(elem.text)
            result_dict[attr_name] = attr_value

    tables = container.find_all('table', class_='table table-bordered table-light mt-2')
    for elem in tables:
        thead = elem.find('thead')
        ths = thead.find_all('th')
        tmp_ths = []
        for th in ths:
            tmp_ths.append(th.text)
        ths = tmp_ths

        tbody = elem.find('tbody', class_='bg-white')

        if 'Mitigation' in thead.text:
            # print('Mitigations')
            contents = []
            trs = tbody.find_all('tr')
            for tr in trs:
                tds = tr.find_all('td')
                idx = 0
                cont_elem = {}
                for td in tds:
                    cont_elem[ths[idx]] = td.text
                    idx += 1
                contents.append(cont_elem)
            result_dict['Mitigations'] = contents

        elif 'Name' in thead.text:
            # print('Examples')
            contents = []
            trs = tbody.find_all('tr')
            for tr in trs:
                tds = tr.find_all('td')
                idx = 0
                cont_elem = {}
                for td in tds:
                    cont_elem[ths[idx]] = td.text
                    idx += 1
                contents.append(cont_elem)
            result_dict['Examples'] = contents

    return result_dict


def tactics_get_page_content(url, tactic_name):
    result_dict = {}

    labels = get_html_label(url)
    container = labels.find('div', id='v-attckmatrix')

    result_dict['Name'] = tactic_name
    result_dict['Description'] = get_real_text(container.find('div', class_='col-md-8 description-body').text)
    attr_card_bodys = container.find_all('div', class_='card-data')

    for elem in attr_card_bodys:
        span_label = elem.find('span')
        attr_name = span_label.text

        if attr_name != "":
            span_label.extract()
            attr_value = get_real_text(elem.text)
            result_dict[attr_name] = attr_value

    tables = container.find_all('table', class_='table table-bordered table-light mt-2')
    for elem in tables:
        thead = elem.find('thead')
        ths = thead.find_all('th')
        tmp_ths = []
        for th in ths:
            tmp_ths.append(th.text)
        ths = tmp_ths

        tbody = elem.find('tbody', class_='bg-white')

        # print('Techniques')
        contents = []
        trs = tbody.find_all('tr')
        for tr in trs:
            tds = tr.find_all('td')
            idx = 0
            cont_elem = {}
            for td in tds:
                cont_elem[ths[idx]] = td.text
                idx += 1
            contents.append(cont_elem)
        result_dict['Techniques'] = contents

    return result_dict


def software_get_page_content(url, sw_name):
    result_dict = {}

    labels = get_html_label(url)
    container = labels.find('div', id='v-attckmatrix')

    result_dict['Name'] = sw_name
    descript_box = container.find('div', class_='col-md-8 description-body')
    result_dict['Description'] = get_real_text(descript_box.text)
    descript_box.extract()
    attr_card_bodys = container.find_all('div', class_='card-data')

    for elem in attr_card_bodys:
        span_label = elem.find('span')
        if span_label == None:
            continue
        attr_name = span_label.text
        span_label.extract()

        attr_value = get_real_text(elem.text)

        result_dict[attr_name] = attr_value

    tables = container.find_all('table', class_='table table-bordered table-light mt-2')
    for elem in tables:
        thead = elem.find('thead')
        ths = thead.find_all('th')
        tmp_ths = []
        for th in ths:
            tmp_ths.append(th.text)
        ths = tmp_ths

        tbody = elem.find('tbody', class_='bg-white')

        if 'Domain' in thead.text:
            # print('Techniques Used')
            tech = []
            trs = tbody.find_all('tr')
            for tr in trs:
                tds = tr.find_all('td')
                idx = 0
                tech_elem = {}
                for td in tds:
                    tech_elem[ths[idx]] = td.text
                    idx += 1
                tech.append(tech_elem)
            result_dict['Techniques Used'] = tech

        elem.extract()

    group_list = container.find_all('a', href=re.compile('/groups/'))
    result_dict['Groups'] = []
    for elem in group_list:
        result_dict['Groups'].append(elem.text)

    return result_dict

##################################################################

#file_exist = Path('C:\\Users\\dlwog\\Desktop\\Groups.json')
#if file_exist.is_file():
#    print('C:\\Users\\dlwog\\Desktop\\Groups.json' + "already exist")

# Group

with open('C:\\Users\\dlwog\\Desktop\\Groups.json', 'w', encoding='utf-8') as json_file:

    group_html_label = get_html_label('https://attack.mitre.org/groups/')

    group_dict = {}
    group_nav = group_html_label.find('div', id="group-nav-desktop-view")
    group_list = group_nav.find_all('a', class_="nav-link side")
    for elem in group_list:
        print(elem.text)

        tmp_group = group_get_page_content('https://attack.mitre.org' + elem['href'], elem.text)
        group_dict[elem.text] = tmp_group

    json.dump(group_dict, json_file, ensure_ascii=False, indent=4)


# Techniques

with open('C:\\Users\\dlwog\\Desktop\\Techniques.json', 'w', encoding='utf-8') as json_file:

    tech_dict = {}

    # Enterprise

    enter_html_label = get_html_label('https://attack.mitre.org/techniques/enterprise')

    enter_list = enter_html_label.find_all('a', class_="nav-link side")
    tech_dict['Enterprise'] = {}
    for elem in enter_list:
        print(elem.text)

        tmp_enter = tech_get_page_content('https://attack.mitre.org' + elem['href'], elem.text)
        tech_dict['Enterprise'][elem.text] = tmp_enter

    # Mobile

    mobile_html_label = get_html_label('https://attack.mitre.org/techniques/mobile')

    mobile_list = mobile_html_label.find_all('a', class_="nav-link side")
    tech_dict['Mobile'] = {}
    for elem in mobile_list:
        print(elem.text)

        tmp_mobile = tech_get_page_content('https://attack.mitre.org' + elem['href'], elem.text)
        tech_dict['Mobile'][elem.text] = tmp_mobile

    # PRE-ATT&CK

    pre_html_label = get_html_label('https://attack.mitre.org/techniques/pre')

    pre_list = pre_html_label.find_all('a', class_="nav-link side")
    tech_dict['PRE-ATT&CK'] = {}
    for elem in pre_list:
        print(elem.text)

        tmp_pre = tech_get_page_content('https://attack.mitre.org' + elem['href'], elem.text)
        tech_dict['PRE-ATT&CK'][elem.text] = tmp_pre

    json.dump(tech_dict, json_file, ensure_ascii=False, indent=4)

# Tactics

with open('C:\\Users\\dlwog\\Desktop\\Tactics.json', 'w', encoding='utf-8') as json_file:

    tactics_dict = {}

    # Enterprise

    enter_html_label = get_html_label('https://attack.mitre.org/tactics/enterprise')

    enter_list = enter_html_label.find_all('a', class_="nav-link side")
    tactics_dict['Enterprise'] = {}
    for elem in enter_list:
        print(elem.text)

        tmp_enter = tactics_get_page_content('https://attack.mitre.org' + elem['href'], elem.text)
        tactics_dict['Enterprise'][elem.text] = tmp_enter

    # Mobile

    mobile_html_label = get_html_label('https://attack.mitre.org/tactics/mobile')

    mobile_list = mobile_html_label.find_all('a', class_="nav-link side")
    tactics_dict['Mobile'] = {}
    for elem in mobile_list:
        print(elem.text)

        tmp_mobile = tactics_get_page_content('https://attack.mitre.org' + elem['href'], elem.text)
        tactics_dict['Mobile'][elem.text] = tmp_mobile

    # PRE-ATT&CK

    pre_html_label = get_html_label('https://attack.mitre.org/tactics/pre')

    pre_list = pre_html_label.find_all('a', class_="nav-link side")
    tactics_dict['PRE-ATT&CK'] = {}
    for elem in pre_list:
        print(elem.text)

        tmp_pre = tactics_get_page_content('https://attack.mitre.org' + elem['href'], elem.text)
        tactics_dict['PRE-ATT&CK'][elem.text] = tmp_pre

    json.dump(tactics_dict, json_file, ensure_ascii=False, indent=4)

# Software

with open('C:\\Users\\dlwog\\Desktop\\Software.json', 'w', encoding='utf-8') as json_file:

    group_html_label = get_html_label('https://attack.mitre.org/software/')

    group_dict = {}
    group_nav = group_html_label.find('div', id="group-nav-desktop-view")
    group_list = group_nav.find_all('a', class_="nav-link side")
    for elem in group_list:
        print(elem.text)

        tmp_group = software_get_page_content('https://attack.mitre.org' + elem['href'], elem.text)
        group_dict[elem.text] = tmp_group

    json.dump(group_dict, json_file, ensure_ascii=False, indent=4)
    