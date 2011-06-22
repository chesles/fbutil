import tornado.web
import tornado.auth
import logging

class RestLogin(tornado.web.RequestHandler, tornado.auth.FacebookMixin):
  @tornado.web.asynchronous
  def get(self):
    if self.get_argument("session", None):
      self.get_authenticated_user(self.async_callback(self._on_auth))
    else:
      self.authenticate_redirect(
          extended_permissions="offline_access,publish_stream,read_stream,read_requests,read_mailbox,email,user_birthday,user_likes,user_relationships,user_notes,read_friendlists"
          )

  def _on_auth(self, user):
    if not user:
      self.redirect("/login.rest")
    else:
      self.set_secure_cookie("rest.userid", str(user['uid']))
      self.set_secure_cookie("rest.session_key", user['session_key'])
      self.redirect('/rest')

class GraphLogin(tornado.web.RequestHandler, tornado.auth.FacebookGraphMixin):
  @tornado.web.asynchronous
  def get(self):
    redirect = 'http://'+self.request.headers['Host']+self.request.path
    if self.get_argument("code", None):
      self.get_authenticated_user(
          redirect_uri = redirect,
          client_id = self.settings['facebook_api_key'],
          client_secret = self.settings['facebook_secret'],
          code = self.get_argument("code"),
          callback = self.async_callback(self._on_auth))
    else:
      self.authorize_redirect(
          redirect_uri = redirect,
          client_id = self.settings['facebook_api_key'],
          extra_params={
            "scope": "offline_access,publish_stream,read_stream,read_requests,read_mailbox,email,user_birthday,user_likes,user_relationships,user_notes,read_friendlists"
          })

  def _on_auth(self, user):
    if not user:
      self.redirect("/login")
    else:
      self.set_secure_cookie("graph.userid", str(user['id']))
      self.set_secure_cookie("graph.access_token", user['access_token'])
      self.redirect('/graph')

class FacebookLogout(tornado.web.RequestHandler):
  def get(self):
    self.clear_cookie("graph.userid")
    self.clear_cookie("graph.access_token")
    self.clear_cookie("rest.userid")
    self.clear_cookie("rest.session_key")
    self.redirect("/")

