
class Facebooked::OauthProvider < OauthProvider::Base
  def self.oauth_provider_handler_info
    {
      :name => 'Facebook'
    }
  end

  def authorize_url
    self.session[:redirect_uri] = self.redirect_uri
    client.auth_code.authorize_url(:redirect_uri => self.redirect_uri, :scope => Facebooked::AdminController.module_options.scopes)
  end

  def access_token(params)
    return false unless self.session[:redirect_uri]

    self.redirect_uri = self.session[:redirect_uri]

    OAuth2::Response.register_parser(:text, 'text/plain') { |body| Rack::Utils.parse_query(body) }

    attempts = 1
    begin
      access_token = client.auth_code.get_token(params[:code], :redirect_uri => self.redirect_uri)
      self.token = access_token.token
      self.refresh_token = access_token.refresh_token
      true
    rescue OAuth2::Error => e
      attempts = attempts.succ
      retry unless attempts > 3
      Rails.logger.error e
      false
    rescue Timeout::Error => e
      Rails.logger.error e
      false
    end
  end

  def client
    @client ||= OAuth2::Client.new(Facebooked::AdminController.module_options.app_id, Facebooked::AdminController.module_options.secret, :site => 'https://graph.facebook.com', :token_url => '/oauth/access_token')
  end

  def facebook
    @facebook ||= OAuth2::AccessToken.new self.client, self.token, :param_name => 'access_token', :mode => :query
  end

  def provider_id
    self.facebook_user_data[:id]
  end

  def get_profile_photo_url
    return @profile_photo_url if @profile_photo_url

    response = Net::HTTP.get_response(URI.parse("http://graph.facebook.com/#{self.provider_id}/picture?type=large"))
    case response
    when Net::HTTPRedirection
      @profile_photo_url = response['location']
    else
      nil
    end
  end

  def get_oauth_user_data
    return @oauth_user_data if @oauth_user_data

    @oauth_user_data = {
      :first_name => self.facebook_user_data[:first_name],
      :last_name => self.facebook_user_data[:last_name],
      :email => self.facebook_user_data[:email],
      :profile_photo_url => self.get_profile_photo_url
    }
  end

  def refresh_token
    self.session[:refresh_token]
  end

  def refresh_token=(refresh_token)
    self.session[:refresh_token] = refresh_token
  end

  def get(path, params={}, headers={})
    attempts = 1
    begin
      self.facebook.get(path, :params => params, :headers => headers).body
    rescue OAuth2::Error => e
      attempts = attempts.succ
      retry unless attempts > 3
      Rails.logger.error e
      '{}'
    end
  end

  def post(path, params={}, headers={})
    begin
      self.facebook.post(path, :params => params, :headers => headers).body
    rescue OAuth2::Error => e
      '{}'
    end
  end

  # returns an array of hashes with name and id of friends
  def friends
    @friends ||=
      begin
        res = JSON.parse self.get '/me/friends'
        res['data'] ? res['data'] : []
      end
  end

  protected

  def facebook_user_data
    @facebook_user_data ||= JSON.parse(self.get('/me')).symbolize_keys
  end
end
