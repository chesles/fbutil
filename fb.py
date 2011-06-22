#!/usr/bin/env python

# fb.py: webapp to interact with facebook APIs at a low level

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.auth
import tornado.escape

import json, logging

from tornado.options import define, options

import auth

define("port", default=8888, help="run on the given port", type=int)
define("address", default='127.0.0.1', help="bind to the given ip", type=str)

class FBHandler(tornado.web.RequestHandler):
  def get_current_user(self):
    graph = self.get_secure_cookie("graph.userid")
    rest = self.get_secure_cookie("rest.userid")
    user = {'graph': graph, 'rest':rest, 'id':graph or rest}
    return user

  def get_fbparams(self, key):
    params = self.get_argument(key, "").encode('utf8')
    if params == "":
      args = {}
    else:
      try:
        args = dict(map(lambda x: str(x).split(":", 1), params.split("|")))
      except:
        self.error_message = "Unable to parse parameters: "+params
        args = {}
    return args

class GraphTest(FBHandler, tornado.auth.FacebookGraphMixin):
  def get(self):
    self.render("templates/graph.html", pretty=True, results="", q="", params="", posts="", json=json)

  @tornado.web.asynchronous
  def post(self):
    args = self.get_fbparams("params")
    post_args = self.get_fbparams("posts")

    logging.warn("**args: "+json.dumps(args))

    self.facebook_request(
        self.get_argument('url', '/me/feed'),
        self.async_callback(self._on_response),
        self.get_secure_cookie('graph.access_token'),
        post_args or None,
        **args
      )

  def _on_response(self, response):
    self.render("templates/graph.html", results=response, json=json,
        pretty=self.get_argument("pretty", "") == "on",
        q=self.get_argument("url", ""), params=self.get_argument("params", ""),
        posts = self.get_argument("posts", ""))

class RestTest(FBHandler, tornado.auth.FacebookMixin):
  def get(self):
    self.render("templates/rest.html", pretty=True, results="", q="", params="", posts="", json=json)

  @tornado.web.asynchronous
  def post(self):
    args = self.get_fbparams("params")
    args.update(self.get_fbparams("posts"))

    logging.warn("**args: "+json.dumps(args))

    self.facebook_request(
        self.get_argument('url', 'status.get'),
        callback = self.async_callback(self._on_response),
        session_key = self.get_secure_cookie('rest.session_key'),
        **args
      )

  def _on_response(self, response):
    self.render("templates/rest.html", results=response, json=json,
        pretty=self.get_argument("pretty", "") == "on",
        q=self.get_argument("url", ""), params=self.get_argument("params", ""),
        posts = self.get_argument("posts", ""))

class Home(FBHandler):
  def get(self):
    self.render("templates/fb.html", results=None, json=json, pretty=False, q='', params='', posts='')

if __name__ == "__main__":
    tornado.options.parse_command_line()
    settings = {
        'static_path': 'static/',
        'login_url': '/login', 'debug':True,
        'cookie_secret': 'cookie_secret_here',
        'facebook_api_key': 'fb_api_key_here',
        'facebook_secret': 'fb_secret_here'
      }
    application = tornado.web.Application([
        (r'/', Home),
        (r'/graph', GraphTest),
        (r'/rest', RestTest),
        (r'/logout', auth.FacebookLogout),
        (r'/login.graph', auth.GraphLogin),
        (r'/login.rest', auth.RestLogin),
      ], **settings)

    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port, address=options.address)
    tornado.ioloop.IOLoop.instance().start()
