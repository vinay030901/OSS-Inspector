import flask
from flask import Flask, request, render_template
from Naked.toolshed.shell import execute_js
from external import find


app = Flask(__name__)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/github_input', methods=['GET', 'POST'])
def github_input():
    return render_template("github_input.html")


@app.route('/npm_input', methods=['GET', 'POST'])
def npm_input():
    return render_template("npm_input.html")


@app.route('/pypi_input', methods=['GET', 'POST'])
def pypi_input():
    return render_template("pypi_input.html")


@app.route('/github_input/github', methods=['GET', 'POST'])
def github():
    if request.method == 'POST':
        link = flask.request.form['link']
        lis = link.split("/")
        username = ""
        repository = ""
        for i in range(len(lis)):
            if lis[i] == "github.com":
                username = lis[i+1]
                repository = lis[i+2]
        userProfileRating, repoNamesUser, popular, foundFunctions, checked, repovalues, committerRating, followerRating, followingRating, vulnerability_l, popularScore, total_score = find(
            username, repository)
        return render_template("github.html", username=username, repository=repository,
                               userProfileRating=userProfileRating, repoNamesUser=repoNamesUser,
                               popular=popular, foundFunctions=foundFunctions, checked=checked,
                               repovalues=repovalues, committerRating=committerRating, followerRating=followerRating,
                               followingRating=followingRating, vulnerability_l=vulnerability_l,
                               popularScore=popularScore, total_score=total_score)
    else:
        return render_template("github.html")


@app.route('/npm_input/npm', methods=['GET', 'POST'])
def npm():
    if request.method == 'POST':
        link = flask.request.form['link']
        lis = link.split("/")
        repository = ""
        for i in range(len(lis)):
            if lis[i] == "npmjs.com":
                repository = lis[i+2]
        success = execute_js('index.js', arguments=repository)
        text_file = open("log.txt", "r")
        data = text_file.read()
        text_file.close()
        data = data.replace(",", "").replace("'", "").replace(":", "")
        lis = data.split()
        user = ""
        for i in range(len(lis)):
            if lis[i] == "homepage":
                user = lis[i+1]
                break
        lis = user.split("/")
        username = ""
        repository = ""
        for i in range(len(lis)):
            if lis[i] == "github.com":
                username = lis[i+1]
                repository = lis[i+2]
        if (repository.endswith("#readme")):
            repository = repository[:len(repository)-7]
        print(username, repository)
        userProfileRating, repoNamesUser, popular, foundFunctions, checked, repovalues, committerRating, followerRating, followingRating, vulnerability_l, popularScore, total_score = find(
            username, repository)
        return render_template("npm.html", username=username, repository=repository,
                               userProfileRating=userProfileRating, repoNamesUser=repoNamesUser,
                               popular=popular, foundFunctions=foundFunctions, checked=checked,
                               repovalues=repovalues, committerRating=committerRating, followerRating=followerRating,
                               followingRating=followingRating, vulnerability_l=vulnerability_l,
                               popularScore=popularScore, total_score=total_score)
    else:
        return render_template("npm.html")


@app.route('/pypi_input/pypi', methods=['GET', 'POST'])
def pypi():
    if request.method == 'POST':
        link = flask.request.form['link']
        lis = link.split("/")
        repository = ""
        for i in range(len(lis)):
            if lis[i] == "pypi.org":
                repository = lis[i+2]
        success = execute_js('index2.js', arguments=repository)
        text_file = open("log2.txt", "r")
        data = text_file.read()
        text_file.close()
        ind = data.find("Source Code")

        if ind != -1:
            web = data[ind+15:data.find("'", ind+15)]
        else:
            ind = data.find("Homepage")
            if ind != -1:
                web = data[ind+11:data.find("'", ind+11)]

        lis = web.split("/")
        username = ""
        repository = ""
        for i in range(len(lis)):
            if lis[i] == "github.com":
                username = lis[i+1]
                repository = lis[i+2]
        userProfileRating, repoNamesUser, popular, foundFunctions, checked, repovalues, committerRating, followerRating, followingRating, vulnerability_l, popularScore, total_score = find(
            username, repository)
        return render_template("pypi.html", username=username, repository=repository,
                               userProfileRating=userProfileRating, repoNamesUser=repoNamesUser,
                               popular=popular, foundFunctions=foundFunctions, checked=checked,
                               repovalues=repovalues, committerRating=committerRating, followerRating=followerRating,
                               followingRating=followingRating, vulnerability_l=vulnerability_l,
                               popularScore=popularScore, total_score=total_score)
    else:
        return render_template("pypi.html")


if __name__ == "__main__":
    app.run(debug=True)
