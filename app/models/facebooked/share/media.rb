
class Facebooked::Share::Media < PostStream::Share::Base

  def self.post_stream_share_handler_info
    {
      :name => 'Facebook'
    }
  end

  def self.setup_header(renderer)
    unless renderer.ajax?
      renderer.require_js('builder')
      renderer.require_js('/components/facebooked/javascript/album.js')
      renderer.require_css('/components/facebooked/stylesheets/album.css')
    end
  end

  def valid_params
    [:id, :name, :link, :type, :count, :picture, :author_id, :author_name]
  end

  def valid?
    is_valid = super
    self.post.errors.add_to_base('Album is not selected') if self.options.errors.length > 0
    is_valid
  end

  def render_form_elements(renderer, form, opts={})
    output = form.hidden_field(:id)
    output << form.hidden_field(:name)
    output << form.hidden_field(:link)
    output << form.hidden_field(:type)
    output << form.hidden_field(:count)
    output << form.hidden_field(:picture)
    output << form.hidden_field(:author_id)
    output << form.hidden_field(:author_name)
    output << '<div class="facebook_album_frame"><div id="facebook_albums"></div><hr class="separator"/></div>'
    output << "<script>FacebookAlbumSelector.ready('#{self.options.id}');</script>" if renderer.ajax?
    output
  end

  def process_request(renderer, params, opts={})
    self.post.link = self.options.link
    self.post.post_type = 'image'
    true
  end

  def render_button(opts={})
    text = opts['title'] || self.title
    handler = self.class.to_s.underscore
    content_tag(:a, text, {:href => 'javascript:void(0);', :onclick => "PostStreamForm.share('#{self.type}', '#{handler}'); FacebookAlbumSelector.init('facebook_albums', '#{self.form_name}');"})
  end

  def image_url
    self.options.picture
  end

  def width
    180
  end

  def name
    self.options.name
  end

  def author_name
    self.options.author_name
  end

  def author_url
    "http://www.facebook.com/profile.php?id=#{self.options.author_id}"
  end

  def provider_name
    'Facebook'
  end

  def provider_url
    'http://www.facebook.com/'
  end

  def embeded_html
    self.options.embeded_html
  end

  class Options < HashModel
    attributes :id => nil, :name => nil, :link => nil, :type => nil, :count => nil, :picture => nil, :embeded_html => nil, :author_id => nil, :author_name => nil

    integer_options :count

    validates_presence_of :id
    validates_presence_of :name
    validates_presence_of :link
    validates_presence_of :type
    validates_presence_of :author_name
    validates_presence_of :author_id

    def validate
      self.errors.add(:link, 'is not a facebook url') unless self.link && self.link =~ /^http:\/\/www\.facebook\.com\//
    end
  end
end
