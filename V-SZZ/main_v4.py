import os
import sys
from antlr4 import *
from CLexer import CLexer
from CParser import CParser
import random
import re

import pickle as pickle

import linecache
import subprocess
import datetime
import time
import hashlib

def get_num_token_mapping(token_file):
    num_token_mapping = dict()

    content = linecache.getlines(token_file)
    for i in xrange(len(content)):
        line_data = content[i]
        #print line_data

        pos_equal_right = line_data.rfind('=')
        
        token = line_data[:pos_equal_right].replace("'","")
        num = line_data[pos_equal_right+1:].strip()
        
        #print token, num
        #print
        
        num_token_mapping[num] = token

    #linecache.clearcache()
    return num_token_mapping

def process_token(token_list, num_token_mapping):
    line_num = 1    

    tmp_str = ''
    tmp_token_str = ''
    for token in token_list:
        #print token
        # [@-1,4:6='int',<32>,1:4]
        '''
        line_arr = token.split(',')
        line_num_tmp = int(line_arr[-1].split(':')[0])
        identifier = line_arr[1].split('=')[1][1:-1]
        id_num = line_arr[2][1:-1]
        '''

        identifier_pos_s = token.find("='")
        identifier_pos_e = token.find("',")
        identifier = token[identifier_pos_s+2:identifier_pos_e]

        linenum_pos_s = token.rfind(',')
        linenum_pos_e = token.rfind(':')
        line_num_tmp = int(token[linenum_pos_s+1:linenum_pos_e])

        idnum_pos_s = token.find(',<')
        idnum_pos_e = token.find('>,')
        id_num = token[idnum_pos_s+2:idnum_pos_e]


        id_token = num_token_mapping[id_num]

        if line_num != line_num_tmp:
            #print tmp_str
            #print tmp_token_str
            #print 
            tmp_str = identifier
            tmp_token_str = id_token
        else: 
            tmp_str += (' ' + identifier)
            tmp_token_str += (' ' + id_token)
        
        line_num = line_num_tmp

def transform(func_info_dict):

    norm_instance_mapping = dict()
    #norm_instance_mapping['foo'] = FUNCALL

    if func_info_dict.has_key('PARAL'):
        parameter_list = func_info_dict['PARAL']
        for para in parameter_list:
            norm_instance_mapping[para] = 'PARAMETER'
    if func_info_dict.has_key('VARAL'):
        var_list = func_info_dict['VARAL']
        for var in var_list:
            norm_instance_mapping[var] = 'VARIABLE'
    ''' 
    if func_info_dict.has_key('FUNCL'):
        func_call_list = func_info_dict['FUNCL']
        for func_call in func_call_list:
            norm_instance_mapping[func_call] = 'FUNCALL'
    if func_info_dict.has_key('TYPEL'):
        type_list = func_info_dict['TYPEL']
        for t in type_list:
            norm_instance_mapping[t] = 'TYPE'
    '''
    return norm_instance_mapping
    
#para: string
#return: hash value of string
def get_hash(s):
    m=hashlib.md5()
    m.update(s)
    return m.hexdigest()

#Save string to file
#para: string to be saved
def save(str_to_save):
    return
    #with open('tmp_info_without_u_new', 'a+') as f:
    #    f.write(str_to_save)


def process_token_with_4norm(token_list, num_token_mapping, func_info_dict):

    norm_instance_mapping = transform(func_info_dict)

    line_num = 1    

    tmp_str = ''
    tmp_token_str = ''

    hashstring_list = []
    hashvalue_list = []

    result_str_to_save = ''

    stmt_list = []
    token_stmt_list = [] 
    hashvalue_list = []

    for token in token_list:
        #print token
        # [@-1,4:6='int',<32>,1:4]
        '''
        line_arr = token.split(',')
        line_num_tmp = int(line_arr[-1].split(':')[0])
        identifier = line_arr[1].split('=')[1][1:-1]
        id_num = line_arr[2][1:-1]
        '''

        identifier_pos_s = token.find("='")
        identifier_pos_e = token.find("',<")
        identifier = token[identifier_pos_s+2:identifier_pos_e] #e.g: int

        linenum_pos_s = token.rfind(',')
        linenum_pos_e = token.rfind(':')
        line_num_tmp = int(token[linenum_pos_s+1:linenum_pos_e]) #e.g: 1

        idnum_pos_s = token.find(',<')
        idnum_pos_e = token.find('>,')
        id_num = token[idnum_pos_s+2:idnum_pos_e] #e.g: 32


        #replace var(specific) to VARIABLE(general)
        #e.g: int a = 5; a => VARIABLE
        #id_token = num_token_mapping[id_num]
        if norm_instance_mapping.has_key(identifier):
            id_token = norm_instance_mapping[identifier]
        elif id_num == '108':  #StringLiteral=108
            id_token = 'StringLiteral'
        else:
            id_token = identifier
        #print id_token

        #print 'id_token', id_token
        if line_num != line_num_tmp:
            #print tmp_str.strip()
            #print tmp_token_str.strip()
            hashvalue = get_hash(tmp_token_str.strip())
            #print hashvalue
            #print 

            ######
            result_str_to_save += (tmp_str.strip() + '\n')
            result_str_to_save += (tmp_token_str.strip() + '\n')
            result_str_to_save += (hashvalue + '\n\n')

            stmt_list.append(tmp_str.strip())
            token_stmt_list.append(tmp_token_str.strip())
            hashvalue_list.append(hashvalue)
            ######            

            tmp_str = identifier
            tmp_token_str = id_token
        else: 
            tmp_str += (' ' + identifier)
            tmp_token_str += (' ' + id_token)
        
        line_num = line_num_tmp
    #print tmp_str.strip()
    #print tmp_token_str.strip()
    hashvalue = get_hash(tmp_token_str.strip())
    #print hashvalue

    ######
    #result_str_to_save += (tmp_str.strip() + '\n')
    #result_str_to_save += (tmp_token_str.strip() + '\n')
    #result_str_to_save += (hashvalue + '\n\n')
    #save(result_str_to_save)

    stmt_list.append(tmp_str.strip())
    token_stmt_list.append(tmp_token_str.strip())
    hashvalue_list.append(hashvalue)
    ######
    
    return [stmt_list, token_stmt_list, hashvalue_list]
    

def get_pos_list(content, filepath):
    pos_list = []
    for i in xrange(len(content)):
        line_data = content[i]
        #if line_data.find(filepath) != -1:
        '''
        try:
            if line_data.strip() == filepath:
                pos_list.append(i)
        except Exception as e:
            print '============================='
            print e
            print '============================='
            print line_data
            print '============================='
            print filepath
            exit(1)
        '''
        #print line_data
        #print filepath
        if line_data.strip() == filepath:
            pos_list.append(i)
        #'''
    pos_list.append(len(content)-1)
    return pos_list

def pre_parse(filepath):
    #print 'filepath', filepath
    cmd = 'java -Xmx1024m -jar FuncParser-opt.jar %s' % filepath
    status, output = subprocess.getstatusoutput(cmd)
    
    '''
    [{'FN:function_name', \
      'PARAL':[para1, para2, ...], \  #parameter list
      'TYPEL':[type1, type2, ...], \  #type list
      'FUNCL':[func1, func2, ...], \  #funcall list
      'VARAL':[var1, var2, ...] \     #variable list
     }, {}]
    '''
    func_detail_list = []

    filename = 'FuncParserResult_' + str(time.time()) + get_hash(filepath) 
    with open(filename, 'w') as f:
        f.write(output)
    
    content = linecache.getlines(filename)
    #content = output.split('\n')

    #to get the start postion of each function    
    func_start_pos_list = get_pos_list(content, filepath)
    #print 'function_start_pos_list', func_start_pos_list

    #for i in xrange(len(content)):
    len_of_list = len(func_start_pos_list)
    for i in xrange(len_of_list-1):

        #print '############################################'

        index_pos = func_start_pos_list[i]
        end_pos = func_start_pos_list[i+1]
        
        line_data = content[index_pos]
        
        func_detail = {}

        function_name = content[index_pos+2].strip()
        function_name = function_name.replace(' ', '')
        para_line = content[index_pos+5]
        vara_line = content[index_pos+6]
        type_line = content[index_pos+7]
        func_call_line = content[index_pos+8]
        
        func_detail['FN'] = function_name
        if len(para_line) > 1:
            #print 'para_line', para_line
            para_list = para_line.strip().split('\t') 
            #print para_list
            #print 
            func_detail['PARAL'] = para_list

        if len(vara_line) > 1:
            #print 'vara_line', vara_line
            variable_list = vara_line.strip().split('\t')
            #print variable_list
            #print 
            func_detail['VARAL'] = variable_list
                
        if len(type_line) > 1:
            #print 'type_line', type_line
            type_list = type_line.strip().split('\t')
            #print type_list
            #print 
            func_detail['TYPEL'] = type_list

        if len(func_call_line) > 1:
            #print 'func_call_line', func_call_line
            func_call_list = func_call_line.strip().split('\t')
            #print func_call_list
            #print     
            func_detail['FUNCL'] = func_call_list
        
        if i !=  len_of_list-2:
            func_content = ''.join(content[index_pos+10:end_pos-3])
        else:
            func_content = ''.join(content[index_pos+10:end_pos])
        func_detail['FUNC_CONTENT'] = func_content 
        
        #print func_detail        
        func_detail_list.append(func_detail) 
    os.system('rm %s' % filename)
    #linecache.clearcache()
    return func_detail_list

def merge_list(init_list):

    init_list.append(2**32)    

    result_list = []
    if len(init_list) < 1:
        return result_list

    index = 0
    length = len(init_list)

    tmp_arr = []
    while index<length-1:
        if init_list[index+1] == init_list[index]+1:
            tmp_arr.append(init_list[index])
        else:
            tmp_arr.append(init_list[index])
            result_list.append(tmp_arr)
            tmp_arr = []
        index += 1
    if init_list[-1] in tmp_arr:
        pass
    else:
        result_list.append([init_list[-1]])

    return result_list[:-1]

def is_end_of_statement(string):

    string = string.strip()
    replaced = re.sub('[ ]{1,}', '', string)
    char = replaced[-1]
    last_two_char = replaced[-2:]

    if string[-4:] == 'else':
        return True
    
    if char != '{' and char != '}' and  \
       char != ':' and char != ';' and \
       char != ')' or last_two_char == '={':
        return True
    else:
        return False

def merge_line(filename):
    content = linecache.getlines(filename)
   
    '''
    content = []
    for line in contents:
        if line.find('#') == 0:
            content.append('\n')
        content.append(line)
    '''

    line_with_comma_end = []  #[2,3,5,6,8,11]
    for i in xrange(len(content)):
        line_data = content[i]
        #print 'line_data', i, line_data
        if len(line_data.strip()) < 2:
            continue
        if is_end_of_statement(line_data):
            line_with_comma_end.append(i)
    
    #print 'line_with_comma_end', line_with_comma_end

    #[[2,3], [5,6], [8], [11]]
    continuous_list = merge_list(line_with_comma_end)

    #print 'continuous_list', continuous_list

    #{2:[0,3], 5:[1,3], 8:[2,2], 11:[3,2]} first_element:[order, len]
    line_num_dict = dict()
    index = 0
    tmp_result_content = []
    for item in continuous_list:
        #print 'item', item
        key = item[0]
        line_num_dict[key] = [index, len(item)+1]
        index += 1
        if item[-1]+1 < len(content):
            item.append(item[-1]+1)
        tmp_str = ''
        for line_num in item:
            tmp_str += (content[line_num].strip())
        if tmp_str.find('{') != -1 and tmp_str.rstrip()[-1] == '{':
            tmp_str = tmp_str.rstrip()[:-1]+'\n'
        tmp_result_content.append(tmp_str+'\n')
    #print 'tmp_result_content', tmp_result_content

    
    result_content = []
    index = 0
    length = len(content)

    flag = True
    while index<length:
        line_data = content[index]
        if line_num_dict.has_key(index):
            result_content.append(tmp_result_content[line_num_dict[index][0]]) 
            index += line_num_dict[index][1]
        else:
            #print 'line_data_before', index, line_data
            #remove '{'
            if line_data.find('{') != -1 and line_data.rstrip()[-1] == '{':
                line_data = line_data.rstrip()[:-1]+'\n'
            #print 'line_data_after', index, line_data
            result_content.append(line_data)
            index += 1
    
    with open(filename, 'w') as f:
        f.write(''.join(result_content))

    #linecache.clearcache()
    #print ''.join(result_content)


def get_input_content(function_content):
    #filename = 'functioncontent_' + str(time.time()) + str(random.random())[-3:]
    filename = 'functionContent_%s_%s' % \
        (str(time.time()), str(random.random())[-9:][:random.randint(3,8)])
    #print '================ start'
    #print function_content
    #print '=============== end'
    with open(filename, 'w') as f:
        f.write(function_content)

    merge_line(filename) #merge line which ends with comma

    input_content = FileStream(filename)
    os.system('rm %s' % filename)
    return input_content


def remove_comment(token_list):
    result_str = ''

    ## [@-1,4:6='int',<32>,1:4]
    ## [@-1,start:end='identifier',<token_id>,line_num:start]

    line_num = 1
    last_pos = 0
    tmp_str = ''
    len_of_identifier = 0
    for token in token_list:
        #print token

        ## Get identifier, e.g: int
        identifier_pos_s = token.find("='")
        identifier_pos_e = token.rfind("',")
        identifier = token[identifier_pos_s+2:identifier_pos_e]
        
        #get length of identifier 
        len_of_identifier = len(identifier)

        ## Get line num, e.g: 1
        linenum_pos_s = token.rfind(',')
        linenum_pos_e = token.rfind(':')
        line_num_tmp = int(token[linenum_pos_s+1:linenum_pos_e])

        ## Get start position, e.g: 6
        start_pos_l = token.rfind(":")
        start_pos_r = token.rfind("]")
        start_pos = int(token[start_pos_l+1:start_pos_r])


        ## Get end position, e.g: 6
        #end_pos_l = token.find(":")
        #end_pos_r = token.find("='")
        #end_pos = int(token[end_pos_l+1:end_pos_r])

        if line_num != line_num_tmp:
            #print tmp_str
            result_str += (tmp_str.encode('utf-8') + '\n')
            #print
            #print line_num_tmp
            tmp_str = (' '*start_pos + identifier)           
        else:
            tmp_str += (' '*(start_pos-last_pos) + identifier)
        last_pos = len(tmp_str) #+ len_of_identifier
        line_num = line_num_tmp
    #print tmp_str
    result_str += (tmp_str.encode('utf-8') + '\n')
    return result_str

def pre_process_remove_comments(function_content):

    ######
    # remove lines that start with '#' (#ifdef, #endif, etc.)
    ######
    content_list = function_content.split('\n')
    result_list = []
    for line in content_list:
        if line.find('#') == 0:
            continue
        result_list.append(line)
    function_content = '\n'.join(result_list)

    #print 'pre_process_remove_comments'
    filename = 'functionContent_%s_%s' % \
	(str(time.time()), str(random.random())[-9:][:random.randint(5,9)])
    #print 'filename', filename
    with open(filename, 'w') as f:
        f.write(function_content)
    #print 'function_content'
    #print function_content
    #cmd = "perl -pe's/[[:^ascii:]]//g' %s" % (filename)
    #status, output = subprocess.getstatusoutput(cmd)
    
    #with open(filename, 'w') as f:
    #    f.write(function_content)
    result_str = None
    try:
        input_f = FileStream(filename)
        lexer = CLexer(input_f)
        tokens = lexer.getAllTokens()

        result_list = []
        for token in tokens:
            #print token
            result_list.append(str(token))

        result_str = remove_comment(result_list)
        #print result_str
    except Exception as e:
        print ('Error in pre_process_remove_comments', e)
    finally:
        os.system('rm %s' % filename)

    return result_str
    #with open(filepath, 'w') as f:
    #    f.write(result_str)
    
def process_func_item(func_item, num_token_mapping):
    function_content = func_item['FUNC_CONTENT']
        
    #print '#########################################'
    #print 'FUNCTION_NAME', func_item['FN']
    #print
 
    ######
    #string_to_save = '#########################################\n'
    #string_to_save += 'FUNCTION_NAME %s \n' % func_item['FN']
    #save(string_to_save)
    ######

    #print '\nfunction: pre_process_remove_comments and non-ascii characters'
    function_content = pre_process_remove_comments(function_content)
    '''
    try:
        function_content = pre_process_remove_comments(function_content)
    except Exception as e:
        print e
        function_content = ''
    '''
    #print 'Processing pre_process_remove_comments is done\n'

    #merge lines that belong to a statement
    input_content = get_input_content(function_content)
    lexer = CLexer(input_content)
    tokens = lexer.getAllTokens()

    result_list = []
    for token in tokens:
        #print token
        result_list.append(str(token))
        
    result_list = process_token_with_4norm(result_list, num_token_mapping, func_item)
    return result_list




def main(argv):

    #filepath: file to be processed (tokenize and hash)
    filepath = argv[1]

    #pre_process_remove_comments(filepath)

    #split c file to multiple functions with getting function name,
    #type list, function call list, function content, para list and variable list
    #return value: list of function_info_dict (include FN, TYPEL, FUNCL, FUNC_CONTENT, PARAL, VARAL)
    function_content_list = pre_parse(filepath)  #with FuncParser-opt.jar

    print ('\n\n***********************************************')
    print ('filepath', filepath)
    print ('length of function_content_list (#functions)', len(function_content_list))
   
    ###### 
    string_to_save = '\n\n***********************************************\n'
    string_to_save += 'filepath %s \n' % filepath
    string_to_save += 'length of function_content_list (#functions) %s \n' % (str(len(function_content_list)))
    save(string_to_save)
    ######

    token_file = argv[2]
    num_token_mapping = get_num_token_mapping(token_file)

    #features_dict = argv[3]

    for func_item in function_content_list:

        result_list = process_func_item(func_item, num_token_mapping)
        print (result_list)
        
        function_name = func_item['FN']
        if func_item.has_key('PARAL'):
            function_paral = func_item['PARAL']
        else:
            function_paral = 'None'
        function_content = func_item['FUNC_CONTENT']
        key = get_hash(function_name + ' '.join(function_paral)+function_content+filepath)
        value = [result_list[2],result_list[0],result_list[1],function_name,filepath]
        #features_dict[key] = value


def main_with_dir(argv):
    dirn = argv[1]
    tokenpath = argv[2]    

    features_dict = {}

    for parent, dirnames, filenames in os.walk(dirn):
        for filename in filenames:
            if filename[-2:] != '.c':
                continue
            main([None, os.path.join(parent, filename), tokenpath, features_dict])
            print ('length of features_dict', len(features_dict.items()))
    #with open('features_dict', 'w') as f:
    #    f.write(pickle.dumps(features_dict))


if __name__ == '__main__':
    main(sys.argv)
    
    #main_with_dir(sys.argv)
