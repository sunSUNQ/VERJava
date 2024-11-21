import os
import subprocess
import re
import json
import sys

from collections import OrderedDict
from unidiff import PatchSet

# YOUR PATH
dir_path = ''


### step one :
# from json file read all cve-commit id pairs 
# use svn get diff file and save

def re_check_file(file, filepath, repo_path, commitID, cmd):
    with open(file, 'rb') as f:   
        readfile = f.read().decode("GBK",errors='ignore')
    fileSize = os.path.getsize(file)
    if readfile.startswith('svn:') or fileSize == 0:
        print(filepath)
        # archive/container/tc5.5.x/catalina/src/share/org/apache/catalina/realm/DataSourceRealm.java
        # \archive\tc5.5.x\trunk\container\catalina\src\share\org\apache\catalina\realm
        if filepath.find('archive/container/tc')!=-1:
            newfilepath = '/'.join(filepath.split('/')[3:])
            newfilepath_v = filepath.split('/')[2]
            newfilepath = 'archive/' + newfilepath_v + '/trunk/container/' + newfilepath
            #print(newfilepath)
            cmd = 'cd %s && svn cat %s -r %s' % (repo_path, newfilepath, commitID) #ori
            s = subprocess.run(cmd, capture_output=True, shell=True, encoding='utf-8')
            with open(file, 'w') as f:
                f.write(s.stdout)
            #print(cmd)
        elif filepath.find('archive/tc')!=-1:
            status,output = subprocess.getstatusoutput(cmd)
            with open(file, 'w') as f:
                f.write(output)
            #print(cmd)
        # archive/container/branches/tc4.1.x/catalina/src/share/org/apache/catalina/core/ApplicationHttpRequest.java
        # archive\tc4.1.x\trunk\container\catalina\src\share\org\apache\catalina\core\ApplicationContext.java
        elif filepath.find('archive/container/branches/tc')!=-1:
            newfilepath = '/'.join(filepath.split('/')[4:])
            newfilepath_v = filepath.split('/')[3]
            newfilepath = 'archive/' + newfilepath_v + '/trunk/container/' + newfilepath
            #print(newfilepath)
            cmd = 'cd %s && svn cat %s -r %s' % (repo_path, newfilepath, commitID) #ori
            s = subprocess.run(cmd, capture_output=True, shell=True, encoding='utf-8')
            with open(file, 'w') as f:
                f.write(s.stdout)
            #print(cmd)
        # archive/trunk/java/org/apache/coyote/http11/Http11Protocol.java
        # archive\tc8.0.x\trunk\java\org\apache\coyote\http11\AbstractHttp11Protocol.java
        elif filepath.startswith('archive/trunk/java/org')!=-1:
            newfilepath = '/'.join(filepath.split('/')[1:])
            newfilepath_v = 'tc8.0.x/'
            newfilepath = 'archive/' + newfilepath_v + newfilepath
            #print(newfilepath)
            cmd = 'cd %s && svn cat %s -r %s' % (repo_path, newfilepath, commitID) #ori
            s = subprocess.run(cmd, capture_output=True, shell=True, encoding='utf-8')
            try:
                with open(file, 'w') as f:
                    f.write(s.stdout)
            except:
                pass
            #print(cmd)
        else:
            #fileSize = os.path.getsize(file)
            #print(fileSize)
            # svn: E195012: Unable to find repository location for 'http://svn.apache.org/repos/asf/tomcat/archive/tc6.0.x/trunk/java/org/apache/catalina/filters/FailedRequestFilter.java' in revision 1200600
            #print(cmd)
            pass


def generate_file(filename_info, repo_path, repo_name, cve_id):
    # get all commit version files .java file
    for filepath, commits in filename_info.items():
        ori_commit = commits[0]
        fix_commit = commits[1]

        filename = filepath.split('/')[-1]
        file = dir_path + '/version_java_file/%s_%s_%s_%s.java' % (repo_name, cve_id, filename.split('.')[0], ori_commit)
        
        cmd = 'cd %s && svn cat %s -r %s' % (repo_path, filepath, ori_commit) #ori
        if not os.path.exists(file):
            s = subprocess.run(cmd, capture_output=True, shell=True, encoding='utf-8')
            with open(file, 'w') as f:
                f.write(s.stdout)

        # some diff file's location is wrong need to check out
        re_check_file(file, filepath, repo_path, ori_commit, cmd)
        
        
        file = dir_path + '/version_java_file/%s_%s_%s_%s.java' % (repo_name, cve_id, filename.split('.')[0], fix_commit)
        
        cmd = 'cd %s && svn cat %s -r %s' % (repo_path, filepath, fix_commit) #fix
        if not os.path.exists(file):
            s = subprocess.run(cmd, capture_output=True, shell=True, encoding='utf-8')
            with open(file, 'w') as f:
                f.write(s.stdout)

        # some diff file's location is wrong need to check out
        re_check_file(file, filepath, repo_path, fix_commit, cmd)

        print("Generating file: " , filename)

def parse_diff(path_to_patch):
    # get diff file patch version before and after commit id
    filename_info = {}
    try:
        with open(path_to_patch, 'r') as f:
            patch_file = f.read()
    except:
        with open(path_to_patch, 'rb') as f:
            patch_file = f.read()
    fix_commit = path_to_patch.split('_')[-1].split('.')[0]
    ori_commit = str(int(fix_commit) - 1)

    #PatchSet can not handle svn diff file
    if str(type(patch_file)).split('\'')[1] == 'bytes' :
        patches = str(patch_file).split('Index: ')
        for num in range(1, len(patches)):
            patch_line_list = patches[num].split('\\n')
            filename = "archive/" + patch_line_list[0].split('\\')[0]
            if not filename.endswith('.java'):
                continue
            filename_info[filename] = [ori_commit, fix_commit]
    else:
        patches = patch_file.split('Index: ')
        for num in range(1, len(patches)):      
            patch_line_list = patches[num].split('\n')
            filename = "archive/" + patch_line_list[0]
            if not filename.endswith('.java'):
                continue
            filename_info[filename] = [ori_commit, fix_commit]

    #{'archive/tc8.0.x/trunk/java/org/apache/naming/factory/ResourceLinkFactory.java': ['1725928', '1725929']}
    return filename_info

### step one :
# get all diff files from /diff_file/
# generate theirs source files(before and after version)
# save them in /version_java_file/

def svn_control_file_generate(repo_path, repo_name, cve_id):
    # for every diff file get their commit version then save java files

    diff_path = dir_path + '/diff_file/'
    diff_path_list = []
    for parent, dirnames, filenames in os.walk(diff_path):
        for filename in filenames:
            if filename.find(repo_name)!=-1 and filename.find(cve_id)!=-1:
                diff_path_list.append(os.path.join(parent, filename)) 

    #patch_info = {}
    cnt = 0
    for diff in diff_path_list:
        if diff.find(cve_id)==-1:
            continue
        cnt = cnt+1
        print("Process %d , total %d" % (cnt, len(diff_path_list)))
        # find svn control type
        if (diff.split('/')[-1].split('.')[0].split('_')[-1]).isdigit():
            # try:
            filename_info = parse_diff(diff)
            #print(filename_info)
            #patch_info[diff.split('/')[-1]] = filename_info
            generate_file(filename_info, repo_path, repo_name, cve_id)
            # except Exception as e:
            #     print(e)
    print()
    print('Generating commit before and after files done!') 


############### step one over



def get_added_line(target_start, target_length, func_patch_target):
    # for each patch, get added lines 
    target_linenum = 0
    added = []
    for target_line in func_patch_target:
        if target_line.startswith('+'):
            if len(target_line.split('+ ')) == 1:
                continue
            if target_line.split('+ ')[1].strip().startswith('//'):
                continue
            added_line = target_line[1:].strip()
            if added_line == '' or added_line == '}' or added_line.startswith('*'):
                continue
            added_num = target_linenum + target_start
            added_list = OrderedDict()
            added_list["target_line_num"] = added_num
            added_list["target_line_code"] = added_line
            added.append(added_list)
        target_linenum += 1
    #print(added)
    return added


def get_removed_line(source_start, source_length, func_patch_source):
    # for each patch, get all removed lines
    source_linenum = 0
    removed = []
    
    for source_line in func_patch_source:
        if source_line.startswith('-'):
            if len(source_line.split('- ')) == 1:
                continue
            if source_line.split('- ')[1].strip().startswith('//'):
                continue
            removed_line = source_line[1:].strip()
            if removed_line == '' or removed_line == '}' or removed_line.startswith('*'):
                continue
            removed_num = source_linenum + source_start
            removed_list = OrderedDict()
            removed_list["source_line_num"] = removed_num
            removed_list["source_line_code"] = removed_line
            removed.append(removed_list)
        source_linenum += 1
    #print(removed)
    return removed


def read_file_list(inputFile):
    # read file each lines
    results = []
    try:
        fin = open(inputFile, 'r')
        for eachLiine in fin.readlines():
            line = eachLiine.strip()
            results.append(line)
        fin.close()
    except:
        with open(inputFile, 'rb') as f:   
            readfile = f.read().decode("GBK",errors='ignore')
        for eachLiine in readfile.split('\n'):
            line = eachLiine.strip()
            results.append(line)
    
    return results


def read_file(inputFile):
    # read file
    results = []
    try:
        fin = open(inputFile, 'r')
        result = fin.read()
        fin.close()
    except:
        with open(inputFile, 'rb') as f:   
            result = f.read().decode("GBK",errors='ignore')
    return result

def patch_func_import_handle(patch_target):
    # import and * patch handle
    normal_line = []
    for one in patch_target:
        if one.find(' *')!=-1 or one.find('/*')!=-1 or one.find('*/')!=-1:
            continue
        elif one.find('import')!=-1:
            continue
        elif one == ' \n':
            continue
        else:
            normal_line.append(one)
    return normal_line 


def patch_func_name_in_patch(patch_target):
    # patch target code have function name, use this as patch_func_name
    patch_func_name = ''
    for one_line in patch_target:
        if one_line.endswith(','):
            # public long process(SSIMediator ssiMediator, String commandName,
            #       String[] paramNames, String[] paramValues, PrintWriter writer) {
            continue
        elif one_line.strip().startswith('.'):
            # if (inputFilters[i].getEncodingName()
            #     .toString().equals(encodingName)) {
            continue
        elif one_line.endswith('&&'):
            # if (context.getIgnoreAnnotations() &&
            continue
        if re.match('.*\(.*\).*\{', one_line):
            if one_line.startswith('+'):
                one_line = one_line.split('+')[1].strip()
                # +// if (headerBufferSize < (8 * 1024)) {
                if one_line.startswith('//'):
                    one_line = one_line.split('//')[1].strip()
            elif one_line.startswith('-'):
                one_line = one_line.split('-')[1].strip()
            else:
                one_line = one_line.strip()

            if one_line.startswith('if'):
                continue
            elif one_line.startswith('//'):
                continue
            elif one_line.startswith('for'):
                continue
            elif one_line.startswith('}'):
                continue
            elif one_line.startswith('switch'):
                continue
            elif one_line.startswith('while'):
                continue
            elif one_line.startswith('try'):
                continue
            elif one_line.find('} else')!=-1:
                continue
            elif one_line.strip().startswith('} else'):
                continue
            elif one_line.find('||')!=-1:
                continue
            elif one_line.find('&&')!=-1:
                continue
            elif one_line.startswith('\''):
                continue
            elif one_line.startswith('!'):
                continue
            elif one_line.find('new ')!=-1:
                # nonces = new LinkedHashMap<String, DigestAuthenticator.NonceInfo>() {
                continue
            elif one_line.find('!')!=-1:
                # !cmdLineArgumentsDecodedPattern.matcher(decodedArgument).matches()) {
                continue
            elif one_line.find('"')!=-1:
                continue
            elif one_line.startswith('#'):
                continue
            elif one_line.startswith('_'):
                continue
            elif one_line.strip().find('synchronized')!=-1:
                continue
            elif one_line.strip().startswith('!') or \
                one_line.strip().startswith('#') or \
                one_line.strip().startswith('_') or \
                one_line.strip().startswith('@') or \
                one_line.strip().startswith('*') or \
                one_line.strip().startswith('for') or \
                one_line.strip().startswith('if') or \
                one_line.strip().startswith('and') or \
                one_line.strip().startswith('.'):
                continue
            else:
                patch_func_name = one_line
                if patch_func_name.strip() != '':
                    patch_func_name = patch_func_name.split('(')[0].strip()
                    if len(patch_func_name.split(' ')) > 1:
                        patch_func_name = patch_func_name.split(' ')[-1]
                    else:
                        patch_func_name = patch_func_name.split(' ')[0]
                if patch_func_name == 'if' or\
                    patch_func_name == 'and' or\
                    patch_func_name == 'catch' or\
                    patch_func_name == 'try' or\
                    patch_func_name == 'while' or\
                    patch_func_name == 'for':
                    patch_func_name = ''
                    continue;
                else:
                    break

    return patch_func_name


def patch_func_name_normal(cve_id, diff_file_name, filename, source_start, repo_name):
    # from one diff file find file version
    # than find that version java file
    # find the patch func name
    path_to_patch = dir_path + '/diff_file/%s' % diff_file_name
    commit_list = parse_diff(path_to_patch)
    patch_func_name = ""
    file_version = commit_list[filename]
    source_version_file = dir_path + 'version_java_file/%s_%s_%s_%s.java' % (repo_name, cve_id, filename.split('/')[-1].split('.')[0], file_version[0])

    if not os.path.isfile(source_version_file):
        print("Do not exists!", source_version_file)
        return ''
    # public static void writeOSState(PrintWriter writer, 
    #                                       int mode) {
    ori_file = read_file(source_version_file)
    new_file = ori_file.replace(',\n', ',')
    # protected static void writeContext(PrintWriter writer, \n
    new_file = new_file.replace(', \n', ',')
    #     public void bind(String name, Object obj, Attributes attrs)
    #   throws NamingException {
    new_file = new_file.replace(')\n', ')').split('\n')


    num = 1
    result = []
    for one_line in new_file:
        if num <= source_start:
            # handle two line situation
            if one_line.find(',\t'):
                # public long process(SSIMediator ssiMediator, String commandName,
                #       String[] paramNames, String[] paramValues, PrintWriter writer) {
                #line = new_file[num-1].strip() + new_file[num].strip()
                result.append(one_line)
                #source_start -= 1
            elif one_line.strip().startswith('.'):
                # if (inputFilters[i].getEncodingName()
                #     .toString().equals(encodingName)) {
                line = new_file[num-1].strip() + new_file[num].strip()
                result.append(line)
            elif one_line.endswith('&&'):
                # if (context.getIgnoreAnnotations() &&
                line = new_file[num-1].strip() + new_file[num].strip()
                result.append(line)
            else:
                result.append(one_line)
            num+=1
    result.reverse()
    #print(result)
    for one_line in result:
        #print(one_line)
        if re.match('.*\(.*\).*\{', one_line):
            if one_line.strip().startswith('if'):
                continue
            elif one_line.strip().startswith('//'):
                continue
            elif one_line.strip().startswith('for'):
                continue
            elif one_line.strip().startswith('}'):
                continue
            elif one_line.strip().startswith('switch'):
                continue
            elif one_line.strip().startswith('while'):
                continue
            elif one_line.strip().startswith('try'):
                continue
            elif one_line.strip().find('} else')!=-1:
                continue
            elif one_line.strip().find('else if')!=-1:
                continue
            elif one_line.strip().startswith('} else'):
                continue
            elif one_line.find('||')!=-1:
                continue
            elif one_line.find('&&')!=-1:
                continue
            elif one_line.strip().startswith('\''):
                continue
            elif one_line.find('new ')!=-1:
                # nonces = new LinkedHashMap<String, DigestAuthenticator.NonceInfo>() {
                continue
            elif one_line.find('"')!=-1:
                continue
            elif one_line.strip().startswith('!'):
                continue
            elif one_line.strip().startswith('#'):
                continue
            elif one_line.strip().startswith('.'):
                continue
            elif one_line.strip().startswith('_'):
                continue
            elif one_line.strip().startswith('@'):
                continue
            elif one_line.strip().find('.')!=-1:
                continue
            elif one_line.strip().find('synchronized')!=-1:
                continue
            elif one_line.strip().startswith('!') or \
                one_line.strip().startswith('#') or \
                one_line.strip().startswith('_') or \
                one_line.strip().startswith('@') or \
                one_line.strip().startswith('*') or \
                one_line.strip().startswith('for') or \
                one_line.strip().startswith('if') or \
                one_line.strip().startswith('and') or \
                one_line.strip().startswith('.'):
                continue
            else:
                patch_func_name = one_line
                if patch_func_name.strip() != '':
                    patch_func_name = patch_func_name.split('(')[0].strip()
                    if len(patch_func_name.split(' ')) > 1:
                        patch_func_name = patch_func_name.split(' ')[-1]
                    else:
                        patch_func_name = patch_func_name.split(' ')[0]
                if patch_func_name == 'if' or\
                    patch_func_name == 'and' or\
                    patch_func_name == 'catch' or\
                    patch_func_name == 'try' or\
                    patch_func_name == 'while' or\
                    patch_func_name == 'for':
                    patch_func_name = ''
                    continue;
                else:
                    break
    

    return patch_func_name


def patch_func_name(cve_id, diff_file_name, filename, func_patch_target, patch_func_source_start, repo_name):
    # handle import and * and /n useless patches
    normal_line = patch_func_import_handle(func_patch_target)
    if normal_line == None:
        print('only import and useless patches!')
        return -1
    patch_func = ''
    # patch target code have function name
    patch_func = patch_func_name_in_patch(func_patch_target)
    # target code do not have fuc, find nearest function as patch_func
    if patch_func == '':
        patch_func = patch_func_name_normal(cve_id, diff_file_name, filename, patch_func_source_start, repo_name)

    # if this patch can not find patch function name, then drop
    if patch_func == '':
        #exit()
        return -1
    return patch_func



### step two :
# get all diff files from /diff_file/
# get added line, line num, deleted line, patch_func, filename, diff_file, source_version
# save them as json in /patch_info/
def svn_control(cve_id, repo_name):
    diff_path = dir_path + '/diff_file/'
    diff_path_list = []
    for parent, dirnames, filenames in os.walk(diff_path):
        for filename in filenames:
            if filename.find(repo_name)!=-1 and filename.find(cve_id)!=-1:
                diff_path_list.append(os.path.join(parent, filename)) 

    num = 1 
    for one_diff in diff_path_list:

        diff_file_name = one_diff.split('/')[-1]
        # get diff type like: CVE-2008-2938_681065.diff(svn)
        if (diff_file_name.split('_')[-1].split('.')[0]).isdigit():
            
            with open(one_diff, 'r') as f:
                patches = f.read()
            # one file as a patch
            patches = patches.split('Index: ')

            for number in range(1, len(patches)):
                patch_line_list = patches[number].split('\n') 
                filename = "archive/" + patch_line_list[0]
                if not filename.endswith('.java'):
                    continue
                patch_list = patches[number].split('@@')
                for one in range(1, len(patch_list), 2):
                    patch_info = patch_list[one]
                    patch_content = patch_list[one+1]

                    func_patch_target = []
                    for one_line in patch_content.split('\n'):
                        if not one_line.startswith('- '):
                            func_patch_target.append(one_line)
                    func_patch_source = []
                    for one_line in patch_content.split('\n'):
                        if not one_line.startswith('+ '):
                            func_patch_source.append(one_line)
                    # @@ -302,12 +305,13 @@
                    source_start = int(patch_info.split(' ')[1].split(',')[0].split('-')[1])
                    source_length = int(patch_info.split(' ')[1].split(',')[1])
                    target_start = int(patch_info.split(' ')[2].split(',')[0].split('+')[1])
                    target_length = int(patch_info.split(' ')[2].split(',')[1])

                    # source_start,source_length,target_start,target_length,section_header
                    patch_func = patch_func_name(cve_id, diff_file_name, filename, func_patch_target, source_start, repo_name)
                    if patch_func == -1:
                        #continue
                        patch_func = 'no'
                    added_line_list = get_added_line(target_start, target_length, func_patch_target)
                    removed_line_list = get_removed_line(source_start, source_length, func_patch_source) 

                    if len(added_line_list)==0 and len(removed_line_list)==0:
                        continue

                    func = OrderedDict()
                    func["cve_id"] = cve_id
                    func["added_line"] = added_line_list
                    func["removed_line"] = removed_line_list
                    func["filename"] = filename
                    func["patch_func"] = patch_func
                    func["diff_file"] = diff_file_name

                    patch_json = []
                    patch_json.append(func)
                    patch_filename = repo_name +'_'+ cve_id +'_'+ one_diff.split('_')[1].split('/')[1] +'_'+ \
                        filename.split('/')[-1].split('.')[0] +'_'+ patch_func + '_' + diff_file_name.split('.')[0].split('_')[-1]
                    patch_info_filename = dir_path + '/patch_info/%s.json' % patch_filename
                    
                    if not os.path.isfile(patch_info_filename):
                        with open(patch_info_filename, 'w') as f:
                            f.write(json.dumps(patch_json))
                    elif os.path.isfile(patch_info_filename):
                        with open(patch_info_filename, 'r') as f:
                            oldjson = json.loads(f.read())
                        # if already in :continue
                        added_all_in = True
                        for one in patch_json[0]['added_line']:
                            if one not in oldjson[0]['added_line']:
                                added_all_in = False
                        removed_all_in = True
                        for one in patch_json[0]['removed_line']:
                            if one not in oldjson[0]['removed_line']:
                                removed_all_in = False
                        if added_all_in and removed_all_in:
                            continue
                        # have some lines needed to add in list
                        if not added_all_in and not removed_all_in:
                            new_added_lines = oldjson[0]['added_line']
                            for new_one_line in patch_json[0]['added_line']:
                                if new_one_line not in new_added_lines:
                                    new_added_lines.append(new_one_line)
                            patch_json[0]['added_line'] = new_added_lines

                            new_removed_lines = oldjson[0]['removed_line']
                            for new_one_line in patch_json[0]['removed_line']:
                                if new_one_line not in new_removed_lines:
                                    new_removed_lines.append(new_one_line)
                            patch_json[0]['removed_line'] = new_removed_lines

                        elif not added_all_in and removed_all_in:
                            new_added_lines = oldjson[0]['added_line']
                            for new_one_line in patch_json[0]['added_line']:
                                if new_one_line not in new_added_lines:
                                    new_added_lines.append(new_one_line)
                            patch_json[0]['added_line'] = new_added_lines
                            patch_json[0]['removed_line'] = oldjson[0]['removed_line']

                        elif added_all_in and not removed_all_in:
                            new_removed_lines = oldjson[0]['removed_line']
                            for new_one_line in patch_json[0]['removed_line']:
                                if new_one_line not in new_removed_lines:
                                    new_removed_lines.append(new_one_line)
                            patch_json[0]['removed_line'] = new_removed_lines
                            patch_json[0]['added_line'] = oldjson[0]['added_line'] 
                        # re save file 
                        if not added_all_in or not removed_all_in:
                            with open(patch_info_filename, 'w') as f:
                                f.write(json.dumps(patch_json))
                            print('File changed: \n', patch_filename)
        print("Process %d , total %d" % (num, len(diff_path_list)))
        num += 1



repo_name = sys.argv[1]
#cve_id = 'CVE-2008-1232'
cve_id = sys.argv[2]

# svn repo path
repo_path = ''

# generate pre-patch and post-patch file for analysis the function name
svn_control_file_generate(repo_path, repo_name, cve_id)

# analysis diff files to get patch_infos
svn_control(cve_id, repo_name)
