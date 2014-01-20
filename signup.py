import os
import re
import hashlib
import hmac
import random
import string
import urllib2
import time
import logging
from xml.dom import minidom
from collections import namedtuple
from datetime import datetime, timedelta
import json

from string import letters

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


SECRET='idjsadioajdoaidassasasmlkdnf'

def hash_str(s):
    return hmac.new(SECRET,s,hashlib.md5).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    s=(h.split('|'))[0]
    if h==make_secure_val(s):
        return s

def make_salt():
    return ''.join(random.choice(string.letters) for i in range(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt=h.split(',')[1]
    return h==make_pw_hash(name,pw,salt)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(render_str(template, **kw))

    def render_json(self,dictionary):
        json_list=json.dumps(dictionary)
        self.response.headers['Content-Type']='application/json; charset=UTF-8'
        self.write(json_list)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/' )

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format='json'
        else:
            self.format='html'


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class User(db.Model):
    username=db.StringProperty(required = True)
    pw_hash=db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username =', name).get()
        return u

    @classmethod
    def register(cls,name,pw,email=None):
        pw_hash=make_pw_hash(name,pw)
        return User(username=name,pw_hash=pw_hash,email=email)


class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self):
        raise NotImplementedError 

class Registration(Signup):
    def done(self):
        name = self.username
        user = User.by_name(name)
        
        if user:
            meg = 'user already exists'
            self.render('signup-form.html', error_username=meg)
        else:
            user=User.register(self.username,self.password,self.email)
            user.put()
            self.login(user)
            self.redirect('/blog/welcome')

class Login(BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        name = self.request.get('username')
        password=self.request.get('password')
        user = User.by_name(name)
        msg = 'invalid login'

        if user:
            username=user.username
            pwh = user.pw_hash
            if valid_pw(username, password,  pwh):
                self.login(user)
                self.redirect('/blog/welcome')
            else:
                self.render('login.html', invalid_login=msg)
        else:
            self.render('login.html', invalid_login=msg)

class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')

class Welcome(BaseHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.username)
        else:
            self.redirect('/blog/signup')


class Blog(db.Model):
    subject=db.StringProperty(required = True)
    content=db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now_add=True)

    def json_dict(self):
        params=dict()
        params['content']=self.content
        params['subject']=self.subject
        params['created']=self.created.strftime("%b %d, %Y")
        params['last_modified']=self.last_modified.strftime("%b %d, %Y")

        return params
        

def get_blogs(queryDB=False):
    key='BLOG'
    val = memcache.get(key)
    if val is None or queryDB:
        logging.error("DB QUERY")
        blogs=db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        start_time=time.time()
        blogs = list(blogs)
        val=(blogs,start_time)
        memcache.set(key, val )

    return val

class MainPage(BaseHandler):
    def render_front(self):
        blogs, start_time = get_blogs()
        time_elapsed=int(time.time()-start_time)
        if self.format=='html':
            self.render("front.html", blogs=blogs,time_elapsed=time_elapsed)
        else:
            blogs=list(blogs)
            self.render_json( [ item.json_dict() for item in blogs ] )

    def get(self):
        self.render_front()


class NewPost(BaseHandler):
    def render_newpost(self, subject="", content="", error=""):
        self.render("newpost.html",subject=subject, content=content, error = error)

    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        
        if subject and content:
            a = Blog(subject=subject, content=content)
            a.put()
            get_blogs(True)
            self.redirect("/blog/%s" %a.key().id())
        else:
            error = "we need both a subject and content!"
            self.render_newpost(subject, content, error)


def get_single_blog(blog_key):
    val=memcache.get(blog_key)
    if val:
        blog,start_time=val
    else:
        blog,start_time= None,0

    return blog,start_time

class PermanentLink(BaseHandler):
    def get(self,post_id):
        post_key='POST_KEY'+post_id
        newBlog,start_time=get_single_blog(post_key)
        time_elapsed=0
        if not newBlog:
            newBlog=Blog.get_by_id(long(post_id))
            start_time=time.time()
            memcache.set(post_key, (newBlog,start_time))
        else:
            time_elapsed=int(time.time()-start_time)

        if self.format=='html':
            subject=newBlog.subject
            content=newBlog.content
            created=newBlog.created
            self.render("post.html", subject=subject, content=content, created=created, time_elapsed=time_elapsed)
        else:
            #jsonString=json.dumps(newBlog.json_dict())
            #l.append(jsonString)
            self.render_json(newBlog.json_dict())
    
class FlushBlogs(BaseHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog/')


class JSONPage(BaseHandler):
    def render_front(self):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        self.render("jsonPage.html", blogs=blogs)

    def get(self):
        self.render_front()


app = webapp2.WSGIApplication([('/blog/signup', Registration),
                               ('/blog/welcome', Welcome),
                               ('/blog/login',Login),
                               ('/blog/logout',Logout),
                               ('/blog/?(?:.json)?', MainPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/(\d+)/?(?:.json)?', PermanentLink),
                               ('/blog/.json',JSONPage),
                               ('/blog/flush/?', FlushBlogs)],
                              debug=True)
