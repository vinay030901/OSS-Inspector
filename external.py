from numpy import append
import requests
import urllib.parse
import os


class verify:

    followerNames = []
    followingNames = []
    repoNames = []
    repovulnerability = {}
    vulnerabilities = 0
    token=os.getenv("token")
    header = f'{token} myToken'
    committerNames = set()
    vulnerableInGivenRepo = []
    file_count = 0

    def __init__(self, username, repository):
        self.username = username
        self.repository = repository

    def checkFollowers(self):
        followers_url = f"https://api.github.com/users/{self.username}/followers"
        followers_data = requests.get(followers_url, headers={
            'Authorization': self.header}).json()

        if isinstance(followers_data, list) == True:
            for i in range(len(followers_data)):
                follower_dictionary = followers_data[i]
                self.followerNames.append(follower_dictionary['login'])
                print(follower_dictionary['login'])

        return self.followerNames

    def checkFollowing(self):
        following_url = f"https://api.github.com/users/{self.username}/following"
        following_data = requests.get(following_url, headers={
            'Authorization': self.header}).json()

        if isinstance(following_data, list) == True:
            for i in range(len(following_data)):
                following_dictionary = following_data[i]
                self.followingNames.append(following_dictionary['login'])
                print(following_dictionary['login'])

        return self.followingNames

    def listRepos(self):
        self.repoNames = []
        repo_url = f"https://api.github.com/users/{self.username}/repos"
        repo_data = requests.get(repo_url, headers={
            'Authorization': self.header}).json()
        if isinstance(repo_data, list) == True:
            for i in range(len(repo_data)):
                repo_dictionary = repo_data[i]
                self.repoNames.append(repo_dictionary['name'])
                print(repo_dictionary['name'])

        return self.repoNames

    def listCommitters(self):
        for i in range(len(self.repoNames)):
            commit_url = f"https://api.github.com/repos/{self.username}/{self.repoNames[i]}/commits"
            commit_data = requests.get(commit_url, headers={
                'Authorization': self.header}).json()
            if isinstance(commit_data, list) == True:
                for i in range(len(commit_data)):
                    commit_dictionary = commit_data[i]
                    try:
                        if commit_dictionary["author"]["login"] != self.username:
                            self.committerNames.add(
                                commit_dictionary["author"]["login"])
                            print(commit_dictionary["author"]["login"])
                    except:
                        pass

        return self.committerNames

    def vulnerabilities_c(self, words, repo):
        c_vulnerabilities = {"strcpy": 2, "wcscpy": 2, "strncpy": 1, "strcat": 1, "wcscat": 2, "strncat": 1, "sprintf": 3,
                             "vsprintf": 3, "snprintf": 1, "strtok": 3, "strtok_r": 1, "strsep": 2, "scanf": 2, "sscanf": 2,
                             "vscanf": 2, "vsscanf": 2, "gets": 3, "ato": 3, "*toa": 2, "strlen": 2, "wcslen": 2, "alloca": 2}
        ans = 0
        this = 0
        for i in words:
            if i.find("(") != -1:
                i = i[:i.find("(")]
            if i in c_vulnerabilities:
                this = c_vulnerabilities[i]
                print(f"C vulernability found: {c_vulnerabilities[i]}")
                if repo == self.repository:
                    self.vulnerableInGivenRepo.append(i)
                if this is not None:
                    ans += this

        return ans

    def vulnerabilities_php(self, words, repo):
        php_vulnerabilities = {"exec": 3, "passthru": 1, "system()": 2, "\`\`": 1,
                               "shell_exec": 1, "popen": 1, "proc_open": 2, "pcntl_exec": 1,
                               "assert": 3, "pregplace('/.*/e',...)": 2, "create_function": 1,
                               "include": 2, "include_once": 2, "require()": 2, "require_once": 2, "$GET": 2, "ob_start": 1,
                               "array_diff_uassoc": 1, "array_diff_ukey": 1, "array_filter": 1, "array_intersect_uassoc": 1,
                               "array_intersect_ukey": 1, "array_map": 1, "array_udiff_assoc": 1, "array_udiff_uassoc": 1,
                               "array_udiff": 1, "array_uintersect_assoc": 1, "array_uintersect_uassoc": 1, "array_uintersect": 1,
                               "array_walk_recursive": 1, "array_walk": 1, "assert_options": 1, "uasort": 1, "uksort": 1, "usort": 1,
                               "preg_replace_callback": 1, "spl_autoload_register": 2, "iterator_apply": 1, "call_user_func": 2,
                               "call_user_func_array": 2, "register_shutdown_function": 3, "register_tick_function": 3,
                               "set_error_handler": 2, "set_exception_handler": 3, "session_set_save_handler": 2, "sqlite_create_aggregate": 3,
                               "sqlite_create_function": 3,
                               "phpinfo": 3, "posix_mkfifo": 2, "posix_getlogin": 2, "posix_ttyname": 1, "getenv": 1, "get_current_user": 2, "proc_get_status": 2, "get_cfg_var": 2, "disk_free_space": 2, "disk_total_space": 2, "diskfreespace": 2, "getcwd": 2, "getlastmo": 2, "getmygid": 2, "getmyinode": 2, "getmypid": 2, "getmyuid": 2,
                               "extract": 2, "parse_str": 2, "putenv": 1, "ini_set": 2, "mail": 2, "header": 1,
                               "proc_nice": 1, "proc_terminate": 1, "proc_close": 1, "pfsockopen": 1, "fsockopen": 1, "apache_child_terminate": 1,
                               "posix_kill": 1, "posix_mkfifo": 1, "posix_setpgid": 1, "posix_setsid": 1, "posix_setuid": 1, "fopen": 2,
                               "tmpfile": 2, "bzopen": 2, "gzopen": 2, "SplFileObject->__construct": 2, "chgrp": 2, "chmod": 2,
                               "chown": 2, "copy": 2, "file_put_contents": 2, "lchgrp": 2, "lchown": 2, "link": 2, "mkdir": 2,
                               "move_uploaded_file": 2, "rename": 2, "rmdir": 2, "symlink": 2, "tempnam": 2, "touch": 2, "unlink": 2,
                               "imagepng": 2, "imagewbmp": 2, "image2wbmp": 2, "imagejpeg": 2, "imagexbm": 2, "imagegif": 2,
                               "imagegd": 2, "imagegd2": 2, "iptcembed": 2, "ftp_get": 2, "ftp_nb_get": 2, "file_exists": 2,
                               "file_get_contents": 2, "file": 2, "fileatime": 2, "filectime": 2, "filegroup": 2, "fileinode": 2,
                               "filemtime": 2, "fileowner": 2, "fileperms": 2, "filesize": 2, "filetype": 2, "glob": 2, "is_dir": 2,
                               "is_executable": 2, "is_file": 2, "is_link": 2, "is_readable": 2, "is_uploaded_file": 2, "is_writable": 2,
                               "is_writeable": 2, "linkinfo": 2, "lstat": 2, "parse_ini_file": 2, "pathinfo": 2, "readfile": 2, "readlink": 2,
                               "realpath": 2, "stat": 2, "gzfile": 2, "readgzfile": 2, "getimagesize": 2, "imagecreatefromgif": 2,
                               "imagecreatefromjpeg": 2, "imagecreatefrompng": 2, "imagecreatefromwbmp": 2, "imagecreatefromxbm": 2,
                               "imagecreatefromxpm": 2, "ftp_put": 2, "ftp_nb_put": 2, "exif_read_data": 2, "read_exif_data": 2,
                               "exif_thumbnail": 2, "exif_imagetype": 2, "hash_file": 2, "hash_hmac_file": 2, "hash_update_file": 2,
                               "md5_file": 2, "sha1_file": 2, "highlight_file": 2, "show_source": 2, "php_strip_whitespace": 2, "get_meta_tags": 2,
                               "GET": 2, "POST": 2, "PUT": 2, "PATCH": 2, "PATCH_POST": 2}
        ans = 0
        this = 0
        for i in words:
            if i.find("(") != -1:
                i = i[:i.find("(")]
            if i in php_vulnerabilities:
                this = php_vulnerabilities[i]
                print(f"Php vulernability found: {php_vulnerabilities[i]}")
                if repo == self.repository:
                    self.vulnerableInGivenRepo.append(i)
                if this is not None:
                    ans += this
        return ans

    def vulnerabilities_py(self, words, repo):
        python_vulnerabilities = {"commands": 3, "os.spawn": 2, "os.popen": 2, "popen2": 3,
                                  "compile": 2, "cPickle.load": 2, "eval": 3, "exec": 3, "execfile": 2, "marshal.load": 2, "marshal.loads": 2,
                                  "os.execl": 2, "os.execle": 2, "os.execv": 2, "os.execve": 2, "os.execvp": 2, "os.execvpe": 2, "os.popen2": 2,
                                  "os.spawnl": 2, "os.spawnle": 2, "os.spawnlp": 2, "os.spawnlpe": 2, "os.spawnv": 2, "os.spawnve": 2, "os.spawnvp": 2,
                                  "os.spawnvpe": 2, "os.startfile": 2, "os.system": 2, "pickle.load": 3, "pickle.loads": 3, "shelve.open": 1,
                                  "subprocess.call": 2, "subprocess.check_call": 2, "subprocess.check_output": 2, "subprocess.Popen": 2, "yaml.load": 2,
                                  "GET": 2, "POST": 2, "PUT": 2, "PATCH": 2}
        ans = 0
        this = 0
        for i in words:
            if i.find("(") != -1:
                i = i[:i.find("(")]
            if i in python_vulnerabilities:
                this = python_vulnerabilities[i]
                print(
                    f"python vulernability found: {python_vulnerabilities[i]}")
                if repo == self.repository:
                    self.vulnerableInGivenRepo.append(i)
                if this is not None:
                    ans += this
        return ans

    def vulnerabilities_java(self, words, repo):
        java_vulnerabilities = {"java.lang.ClassLoader.defineClass": 2, "java.net.URLClassLoader": 2, "java.beans.Instrospector.getBeanInfo": 3,
                                "java.io.File": 2, "java.io.File.delete": 2, "java.io.File.renameTo": 2, "java.io.File.listFiles": 2, "java.io.File.list": 2,
                                "java.io.FileInputStream": 3, "java.io.FileOutputStream": 3, "java.io.FileReader": 3, "java.io.FileWriter": 3, "java.io.RandomAccessFile": 3,
                                "System.setProperty": 1, "System.getProperties": 1, "System.getProperty": 1,
                                "System.load": 1, "System.loadLibrary": 1,
                                "Runtime.exec": 2, "ProcessBuilder": 2,
                                "java.awt.Robot.keyPress/keyRelease": 2, "java.awt.Robot.mouseMove/mousePress/mouseRelease": 2,
                                "java.lang.Class.getDeclaredMethod": 3, "java.lang.Class.getDeclaredField": 3, "java.lang.reflection.Method.invoke": 2,
                                "java.lang.reflection.Field.set": 2, "java.lang.reflection.Field.get": 2, "javax.script.ScriptEngine.eval": 3,
                                "GET": 2, "POST": 2, "PUT": 2, "PATCH": 2}
        ans = 0
        this = 0
        for i in words:
            if i.find("(") != -1:
                i = i[:i.find("(")]
            if i in java_vulnerabilities:
                this = java_vulnerabilities[i]
                print(f"Java vulernability found: {java_vulnerabilities[i]}")
                if repo == self.repository:
                    self.vulnerableInGivenRepo.append(i)
                if this is not None:
                    ans += this
        return ans

    def vulnerabilities_js(self, words, repo):
        js_vulnerabilities = {"eval": 3, "settimeOut": 2, "setinterval": 2, "function": 2, "yaml": 2, "location.href": 2, "document.url": 3,
                              "document.cookies": 2, "sessionStorage": 1, "localStorage": 2, "navigation.referrer": 2, "window.name": 1, "history": 1,
                              "postmessage": 2, "getcookie": 2, "setcookie": 2, "indexof": 2, "split": 1, "fromcharcode": 1, "tocharcode": 1, "charcodeat": 1,
                              "window.setinterval": 1, "window.settimeout": 2, "document.writein": 1, "document.writeout": 1,
                              "location.assign": 1, "location.replace": 1, "createxmlhttprequest": 2, "unescape": 1, "document.write": 1,
                              "GET": 2, "POST": 2, "PUT": 2, "PATCH": 2}
        ans = 0
        this = 0
        for i in words:
            if i.find("(") != -1:
                i = i[:i.find("(")]
            if i in js_vulnerabilities:
                this = js_vulnerabilities[i]
                print(
                    f"Javascript vulernability found: {js_vulnerabilities[i]}")
                if repo == self.repository:
                    self.vulnerableInGivenRepo.append(i)
                if this is not None:
                    ans += this
        return ans

    def scoreUserOnFollower(self, follower_count):
        score = 0
        if follower_count <= 5:
            score = 1
        elif follower_count <= 15:
            score = 2
        elif follower_count <= 25:
            score = 3
        elif follower_count <= 35:
            score = 4
        elif follower_count <= 45:
            score = 5
        elif follower_count <= 55:
            score = 6
        elif follower_count <= 65:
            score = 7
        elif follower_count <= 75:
            score = 8
        elif follower_count <= 85:
            score = 9
        elif follower_count <= 95:
            score = 10
        elif follower_count <= 105:
            score = 11
        else:
            score = 12
        print("user score: " + str(score))
        return score

    def userRating(self):
        rating = 0
        user_url = f"https://api.github.com/users/{self.username}"

        user_data = requests.get(user_url, headers={
            'Authorization': self.header}).json()
        followers_count = user_data['followers']
        rating += self.scoreUserOnFollower(followers_count)
        following_count = user_data['following']
        if (following_count > 10):
            rating += 2
        if (user_data['location'] != None):
            rating += 2
        if (user_data['name'] != None):
            rating += 2

        if (user_data['hireable'] != None):
            rating += 2

        if (user_data['company'] != None):
            rating += 2

        if (user_data['bio'] != None):
            rating += 2

        if (user_data['email'] != None):
            rating += 2

        if (user_data['blog'] != None):
            rating += 2

        if (user_data['twitter_username'] != None):
            rating += 2

        print(f"user total rating: {rating}")
        return rating

    def check_content(self, file_urls, repo):
        for i in range(len(file_urls)):
            name = file_urls[i]
            if name.endswith(".cpp") or name.endswith(".c") or name.endswith(".cc"):
                str = requests.get(name, headers={
                    'Authorization': self.header}).text
                lis = str.split()
                it = self.vulnerabilities_c(lis, repo)
                if it is not None:
                    self.vulnerabilities += it
                    self.repovulnerability[repo] += it

            elif name.endswith(".py"):
                str = requests.get(name, headers={
                    'Authorization': self.header}).text
                lis = str.split()
                it = self.vulnerabilities_py(lis, repo)
                if it is not None:
                    self.vulnerabilities += it
                    self.repovulnerability[repo] += it

            elif name.endswith(".java"):
                str = requests.get(name, headers={
                    'Authorization': self.header}).text
                lis = str.split()
                it = self.vulnerabilities_java(lis, repo)
                if it is not None:
                    self.vulnerabilities += it
                    self.repovulnerability[repo] += it

            elif name.endswith(".js"):
                str = requests.get(name, headers={
                    'Authorization': self.header}).text
                lis = str.split()
                it = self.vulnerabilities_js(lis, repo)
                if it is not None:
                    self.vulnerabilities += it
                    self.repovulnerability[repo] += it

            elif name.endswith(".php"):
                str = requests.get(name, headers={
                    'Authorization': self.header}).text
                lis = str.split()
                it = self.vulnerabilities_php(lis, repo)
                if it is not None:
                    self.vulnerabilities += it
                    self.repovulnerability[repo] += it

            # elif name.endswith(".cs"):
            #     it = self.vulnerabilities_js(file_content)
            #     if it is not None:
            #         self.vulnerabilities += it
            # elif name.endswith(".sh"):
            #     it = self.vulnerabilities_js(file_content)
            #     if it is not None:
            #         self.vulnerabilities += it

    def repoRating(self):
        for i in range(len(self.repoNames)):
            print(f"for repository {self.repoNames[i]}")
            file_urls = []
            self.repovulnerability[self.repoNames[i]] = 0
            first_url = f"https://api.github.com/repos/{self.username}/{self.repoNames[i]}/git/refs"
            first_res = requests.get(first_url, headers={
                'Authorization': self.header}).json()

            if isinstance(first_res, list) == True:
                dict = first_res[0]
                object = dict["object"]
                sha = object['sha']
                url = f"https://api.github.com/repos/{self.username}/{self.repoNames[i]}/git/trees/{sha}?recursive=1"
                res = requests.get(url, headers={
                    'Authorization': self.header}).json()

                api = f"https://raw.githubusercontent.com/{self.username}/{self.repoNames[i]}/master/"
                for file in res["tree"]:
                    if file["type"] == "blob":
                        path = file["path"]
                        path = urllib.parse.quote(path)
                        ans = api+path
                        print(f"path: {ans}")
                        file_urls.append(ans)
                        ans = ""
                self.file_count += len(file_urls)
            self.check_content(file_urls, self.repoNames[i])
        return self.vulnerabilities

    def popularity(self, repository):
        ans = 0
        for i in range(len(self.repoNames)):
            if self.repoNames[i] == repository:
                repo_url = f"https://api.github.com/repos/{self.username}/{self.repoNames[i]}"
                repo_data = requests.get(repo_url, headers={
                    'Authorization': self.header}).json()
                stars = repo_data['stargazers_count']
                forks_count = repo_data['forks_count']
                watchers_count = repo_data['watchers_count']
                issues_count = repo_data['open_issues_count']
                ans = stars+watchers_count+forks_count-2*issues_count
                print(f"popularity: {ans}")

        if ans > 1000:
            return "very popular", 20
        elif ans > 500:
            return "popular", 15
        elif ans > 200:
            return "average", 10
        else:
            return "not popular", 5


def vulnerability_level(ratingAverage):
    if ratingAverage <= 1:
        return 50
    elif ratingAverage <= 2:
        return 40
    elif ratingAverage <= 3:
        return 30
    elif ratingAverage <= 4:
        return 20
    elif ratingAverage <= 5:
        return 10
    else:
        return 0


def find(username, repository):
    committerRating = {}  # name and rating of every committer
    followerRating = {}  # name and rating of every follower
    followingRating = {}  # name and rating of every following
    repoNamesUser = []  # repository names of the user
    file_count = 0  # total number of files the repositories had
    total_vulnerabilites = 0  # total amount of vulnerabilities found
    user = verify(username, repository)  # the object of the user
    userProfileRating = user.userRating()  # profile rating of the user of 30
    print("userProfileRating: " + str(userProfileRating))
    repoNamesUser = user.listRepos()  # list of repositories of the user
    print("repoNamesUser: " + str(repoNamesUser))
    repoRating = user.repoRating()  # repository ratings
    print("repoRating: " + str(repoRating))
    total_vulnerabilites += repoRating  # added to the total ratings
    file_count += user.file_count  # adding the counf of files of the user
    print("file_count: " + str(file_count))
    # popular rating and popularity score of the user
    popular, popularScore = user.popularity(repository)
    print("popularScore: " + str(popularScore))
    # vulnerable function found in the user repos
    foundFunctions = user.vulnerableInGivenRepo
    repovalues = user.repovulnerability  # vulnerability of the given repository
    checked = 0

    # for committers
    if (len(repoNamesUser) < 40):
        committerList = user.listCommitters()
        committers = []
        if (len(committerList) > 0):
            for i in committerList:
                print("committer: ", str(i))
                committer = verify(i, "$")
                committerRating[i] = committer.userRating()
                this = committerRating[i]
                repoNames = committer.listRepos()
                print("committer repo: ", str(repoNames))
                repoRating = committer.repoRating()
                total_vulnerabilites += repoRating
                committerRating[i] = repoRating+this
                file_count += committer.file_count
                committers.append(i)
    else:
        checked += 1

    # for follower
    if (len(repoNamesUser) < 20):
        follower_list = user.checkFollowers()
        for i in range(len(follower_list)):
            follower = verify(follower_list[i], "$")
            # print("found follower: ", follower_list[i])
            followerRating[follower_list[i]] = follower.userRating()
            this = followerRating[follower_list[i]]
            # repoNames = follower.listRepos()
            # repoRating = follower.repoRating()
            # total_vulnerabilites += repoRating
            followerRating[follower_list[i]] = repoRating+this
            file_count += follower.file_count
    else:
        checked += 1

    # print(repoNamesUser)
    # for following
    if (len(repoNamesUser) < 10):
        following_list = user.checkFollowing()
        if (len(following_list) > 0):
            for i in range(len(following_list)):
                following = verify(following_list[i], "!")
                # print("following: ", following_list[i])
                followingRating[following_list[i]] = following.userRating()
                this = followingRating[following_list[i]]
                repoNames = following.listRepos()
                repoRating = following.repoRating()
                total_vulnerabilites += repoRating
                followingRating[following_list[i]] = repoRating + this
                file_count += following.file_count
    else:
        checked += 1

    vulnerability_l = vulnerability_level(
        total_vulnerabilites//file_count)  # vulnerability score of the user
    total_score = popularScore+vulnerability_l + \
        userProfileRating  # total score of the user
    return userProfileRating, repoNamesUser, popular, foundFunctions, checked, repovalues, committerRating, followerRating, followingRating, vulnerability_l, popularScore, total_score
