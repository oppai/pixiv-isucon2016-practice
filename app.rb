require 'sinatra/base'
require 'mysql2'
require 'rack-flash'
require 'shellwords'
require "rack-lineprof"
require 'redis'
require 'parallel'
require 'active_record'

ActiveRecord::Base.establish_connection(
  adapter:  "mysql2",
  host: ENV['ISUCONP_DB_HOST'] || 'localhost',
  port: ENV['ISUCONP_DB_PORT'] && ENV['ISUCONP_DB_PORT'].to_i,
  username: ENV['ISUCONP_DB_USER'] || 'root',
  password: ENV['ISUCONP_DB_PASSWORD'],
  database: ENV['ISUCONP_DB_NAME'] || 'isuconp',
)

require_relative './models/user'
require_relative './models/comment'
require_relative './models/post'


module Isuconp
  class App < Sinatra::Base
    use Rack::Session::Memcache, autofix_keys: true, secret: ENV['ISUCONP_SESSION_SECRET'] || 'sendagaya'
    use Rack::Flash
    set :public_folder, File.expand_path('../../public', __FILE__)
    use Rack::Lineprof

    UPLOAD_LIMIT = 10 * 1024 * 1024 # 10mb

    POSTS_PER_PAGE = 20

    helpers do
      def redis
        unless @redis
          @redis = Redis.new
        end
        @redis
      end

      def config
        @config ||= {
          db: {
            host: ENV['ISUCONP_DB_HOST'] || 'localhost',
            port: ENV['ISUCONP_DB_PORT'] && ENV['ISUCONP_DB_PORT'].to_i,
            username: ENV['ISUCONP_DB_USER'] || 'root',
            password: ENV['ISUCONP_DB_PASSWORD'],
            database: ENV['ISUCONP_DB_NAME'] || 'isuconp',
          },
        }
      end

      def db()
        return Thread.current[:isuconp_db] if Thread.current[:isuconp_db]
        client = Mysql2::Client.new(
          host: config[:db][:host],
          port: config[:db][:port],
          username: config[:db][:username],
          password: config[:db][:password],
          database: config[:db][:database],
          encoding: 'utf8mb4',
          reconnect: true,
        )
        client.query_options.merge!(symbolize_keys: true, database_timezone: :local, application_timezone: :local)
        Thread.current[:isuconp_db] = client
        client
      end

      def db_initialize
        sql = []
        sql << 'DELETE FROM users WHERE id > 1000'
        sql << 'DELETE FROM posts WHERE id > 10000'
        sql << 'DELETE FROM comments WHERE id > 100000'
        sql << 'UPDATE users SET del_flg = 0'
        sql << 'UPDATE users SET del_flg = 1 WHERE id % 50 = 0'
        sql.each do |s|
          db.prepare(s).execute
        end
      end

      def try_login(account_name, password)
        user = User.find_by_account_name_and_del_flg(account_name, 0)
        #user = db.prepare('SELECT * FROM users WHERE account_name = ? AND del_flg = 0').execute(account_name).first

        if user && calculate_passhash(user[:account_name], password) == user[:passhash]
          return user
        elsif user
          return nil
        else
          return nil
        end
      end

      def validate_user(account_name, password)
        if !(/\A[0-9a-zA-Z_]{3,}\z/.match(account_name) && /\A[0-9a-zA-Z_]{6,}\z/.match(password))
          return false
        end

        return true
      end

      def digest(src)
        # opensslのバージョンによっては (stdin)= というのがつくので取る
        `printf "%s" #{Shellwords.shellescape(src)} | openssl dgst -sha512 | sed 's/^.*= //'`.strip
      end

      def calculate_salt(account_name)
        digest account_name
      end

      def calculate_passhash(account_name, password)
        digest "#{password}:#{calculate_salt(account_name)}"
      end

      def get_session_user()
        if session[:user]
          #db.prepare('SELECT * FROM `users` WHERE `id` = ?').execute(
          #  session[:user][:id]
          #).first
          User.find_by_id(session[:user][:id])
        else
          nil
        end
      end

      def get_first_posts()
      	# @@posts_result ||= 
        # Thread.current[:first_posts] ||= db.query('SELECT `id`, `user_id`, `body`, `created_at`, `mime` FROM `posts` ORDER BY `created_at` DESC LIMIT ' + (POSTS_PER_PAGE+100).to_s).to_a(:as => :hash)
        Thread.current[:first_posts] ||= Post.order(created_at: :desc).limit(POSTS_PER_PAGE+100).to_a
      end
      # FIXME must delete from all thread
      def expire_first_posts()
        # @@posts_result = nil
        Thread.current[:first_posts] = nil
      end
      def get_make_posts()
        results = get_first_posts()
        Thread.current[:make_posts] ||= make_posts(results)
      end
      # FIXME must delete from all thread
      def expire_make_posts()
        Thread.current[:make_posts] = nil
      end

      def comment_count_init(user_id)
        key = "user_comment" + user_id.to_s
        Thread.current[key.to_sym] = 0
      end
      def comment_count_increment(user_id)
        key = "user_comment" + user_id.to_s
        unless Thread.current[key.to_sym]
          Thread.current[key.to_sym] = get_comment_count(user_id) + 1
        else
          Thread.current[key.to_sym] += 1
        end
      end
      def get_comment_count(user_id)
        key = "user_comment" + user_id.to_s
        #Thread.current[key.to_sym] ||= db.prepare('SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?').execute(
        #  user_id
        #).first[:count]
        Thread.current[key.to_sym] ||= Comment.where(user_id: user_id).count
      end

      def make_posts(results, all_comments: false)
        posts = []
        results.to_a.each do |post|
          post_hash = post.attributes.with_indifferent_access
          #post[:comment_count] = db.prepare('SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?').execute(
          #  post[:id]
          #).first[:count]
          _comments = Comment.where(post_id: post[:id]).to_a
          post_hash[:comment_count] = _comments.count

          #query = 'SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC'
          #unless all_comments
          #  query += ' LIMIT 3'
          #end
          #comments = db.prepare(query).execute(
          #  post[:id]
          #).to_a
          comments = (if all_comments
                        _comments.sort_by(&:created_at).reverse
                     else
                        _comments.sort_by(&:created_at).reverse.take(3)
                     end).map do |comment|
                       c = comment.attributes.with_indifferent_access
                       c[:user] = User.find_by_id(comment[:user_id]) 
                       c
                     end
          #comments = comments.each do |comment|
          #  comment[:user] = db.prepare('SELECT * FROM `users` WHERE `id` = ?').execute(
          #    comment[:user_id]
          #  ).first
          #  #comment = comment.attributes.with_indifferent_access
          #  #comment[:user] = User.find_by_id(comment[:user_id])
          #end
          post_hash[:comments] = comments.reverse

          #post_hash[:user] = db.prepare('SELECT * FROM `users` WHERE `id` = ?').execute(
          #  post_hash[:user_id]
          #).first
          post_hash[:user] = User.find_by_id(post_hash[:user_id])

          posts.push(post_hash) unless post_hash[:user][:del_flg]
          break if posts.length >= POSTS_PER_PAGE
        end

        posts
      end

      def image_url(post)
        ext = ""
        if post[:mime] == "image/jpeg"
          ext = ".jpg"
        elsif post[:mime] == "image/png"
          ext = ".png"
        elsif post[:mime] == "image/gif"
          ext = ".gif"
        end

        "/image/#{post[:id]}#{ext}"
      end

      def save_image(post)
        File.open(File.expand_path('../../public', __FILE__) + image_url(post),'w') do |file|
          file.write(post[:imgdata])
        end
      end
    end

    get '/initialize' do
      db_initialize
      # save image from db
      #db.query('SELECT * FROM `posts`').each do |post|
      #  save_image(post)
      #end

      #Parallel.each(db.query('SELECT id FROM users')) do |user|
      #  get_comment_count(user[:id])
      #end

      expire_first_posts()
      expire_make_posts()
      return 200
    end

    get '/login' do
      if get_session_user()
        redirect '/', 302
      end
      erb :login, layout: :layout, locals: { me: nil }
    end

    post '/login' do
      if get_session_user()
        redirect '/', 302
      end

      user = try_login(params['account_name'], params['password'])
      if user
        session[:user] = {
          id: user[:id]
        }
        session[:csrf_token] = SecureRandom.hex(16)
        redirect '/', 302
      else
        flash[:notice] = 'アカウント名かパスワードが間違っています'
        redirect '/login', 302
      end
    end

    get '/register' do
      if get_session_user()
        redirect '/', 302
      end
      erb :register, layout: :layout, locals: { me: nil }
    end

    post '/register' do
      if get_session_user()
        redirect '/', 302
      end

      account_name = params['account_name']
      password = params['password']

      validated = validate_user(account_name, password)
      if !validated
        flash[:notice] = 'アカウント名は3文字以上、パスワードは6文字以上である必要があります'
        redirect '/register', 302
        return
      end

      user = User.find_by_account_name(account_name)
      #user = db.prepare('SELECT 1 FROM users WHERE `account_name` = ?').execute(account_name).first
      if user
        flash[:notice] = 'アカウント名がすでに使われています'
        redirect '/register', 302
        return
      end

      last_user = User.create(account_name: account_name, passhash: calculate_passhash(account_name, password))
      #query = 'INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)'
      #db.prepare(query).execute(
      #  account_name,
      #  calculate_passhash(account_name, password)
      #)

      session[:user] = {
        id: last_user.id
      }
      session[:csrf_token] = SecureRandom.hex(16)
      comment_count_init(last_user.id)

      redirect '/', 302
    end

    get '/logout' do
      session.delete(:user)
      redirect '/', 302
    end

    get '/' do
      me = get_session_user()

      posts = get_make_posts()

      erb :index, layout: :layout, locals: { posts: posts, me: me }
    end

    get '/@:account_name' do
      user = User.find_by_account_name_and_del_flg(params[:account_name], 0)
      #user = db.prepare('SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0 LIMIT 1').execute(
      #  params[:account_name]
      #).first

      if user.nil?
        return 404
      end

      results = Post.where(user_id: user[:id]).order(created_at: :desc).limit(POSTS_PER_PAGE + 100)
      #results = db.prepare('SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT ?').execute(
      #  user[:id],
      #  POSTS_PER_PAGE + 100 
      #)
      posts = make_posts(results)

      comment_count = get_comment_count(user[:id])

      #post_ids = db.prepare('SELECT `id` FROM `posts` WHERE `user_id` = ?').execute(
      #  user[:id]
      #).map{|post| post[:id]}
      #post_count = post_ids.length
      post_ids = Post.where(user_id: user[:id]).select(:id).to_a
      post_count = post_ids.count

      commented_count = 0
      if post_count > 0
        #placeholder = (['?'] * post_ids.length).join(",")
        #commented_count = db.prepare("SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN (#{placeholder})").execute(
        #  *post_ids
        #).first[:count]
        commented_count = Comment.where(post_id: post_ids).count
      end

      me = get_session_user()

      erb :user, layout: :layout, locals: { posts: posts, user: user, post_count: post_count, comment_count: comment_count, commented_count: commented_count, me: me }
    end

    get '/posts' do
      max_created_at = params['max_created_at']
      #results = db.prepare('SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC LIMIT ?').execute(
      #  max_created_at.nil? ? nil : Time.iso8601(max_created_at).localtime,
      #  POSTS_PER_PAGE + 100
      #)
      results = if max_created_at.nil?
                  []
                else
                  #Post.where("created_at <= #{Time.iso8601("2016-01-02T11:46:22+09:00").localtime}").order(created_at: :desc).limit(POSTS_PER_PAGE + 100).to_a
                  Post.where("created_at <= ?", Time.iso8601(max_created_at).localtime).order(created_at: :desc).limit(POSTS_PER_PAGE + 1000).to_a
                end
      posts = make_posts(results)

      erb :posts, layout: false, locals: { posts: posts }
    end

    get '/posts/:id' do
      results = [Post.find_by_id(params[:id])]
      #results = db.prepare('SELECT * FROM `posts` WHERE `id` = ?').execute(
      #  params[:id]
      #)
      posts = make_posts(results, all_comments: true)

      return 404 if posts.length == 0

      post = posts[0]

      me = get_session_user()

      erb :post, layout: :layout, locals: { post: post, me: me }
    end

    post '/' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if params['csrf_token'] != session[:csrf_token]
        return 422
      end

      if params['file']
        mime = ''
        # 投稿のContent-Typeからファイルのタイプを決定する
        if params["file"][:type].include? "jpeg"
          mime = "image/jpeg"
        elsif params["file"][:type].include? "png"
          mime = "image/png"
        elsif params["file"][:type].include? "gif"
          mime = "image/gif"
        else
          flash[:notice] = '投稿できる画像形式はjpgとpngとgifだけです'
          redirect '/', 302
        end

        if params['file'][:tempfile].read.length > UPLOAD_LIMIT
          flash[:notice] = 'ファイルサイズが大きすぎます'
          redirect '/', 302
        end

        params['file'][:tempfile].rewind
        #query = 'INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)'
        #db.prepare(query).execute(
        #  me[:id],
        #  mime,
        #  "",# params["file"][:tempfile].read,
        #  params["body"],
        #)
        last_post = Post.create(user_id: me[:id], mime: mime, imgdata: "", body: params["body"])
        #pid = db.last_id
        pid = last_post.id
	post = {
          id: pid,
          mime: mime,
          imgdata: params["file"][:tempfile].read
        }
        save_image(post)
        expire_first_posts()
        expire_make_posts()
        redirect "/posts/#{pid}", 302
      else
        flash[:notice] = '画像が必須です'
        redirect '/', 302
      end
    end

    post '/comment' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if params["csrf_token"] != session[:csrf_token]
        return 422
      end

      unless /\A[0-9]+\z/.match(params['post_id'])
        return 'post_idは整数のみです'
      end
      post_id = params['post_id']

      #query = 'INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)'
      #db.prepare(query).execute(
      #  post_id,
      #  me[:id],
      #  params['comment']
      #)
      Comment.create(post_id: post_id, user_id: me[:id], comment: params["comment"])
      comment_count_increment(me[:id])

      redirect "/posts/#{post_id}", 302
    end

    get '/admin/banned' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      unless me[:authority]
        return 403
      end

      #users = db.query('SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC')
      users = User.where(authority: 0, del_flg: 0).order(created_at: :desc).to_a

      erb :banned, layout: :layout, locals: { users: users, me: me }
    end

    post '/admin/banned' do
      me = get_session_user()

      if me.nil?
        redirect '/', 302
      end

      unless me[:authority]
        return 403
      end

      if params['csrf_token'] != session[:csrf_token]
        return 422
      end

      #query = 'UPDATE `users` SET `del_flg` = ? WHERE `id` = ?'
      #params['uid'].each do |id|
      #  db.prepare(query).execute(1, id.to_i)
      #end
      User.where(id: params['uid']).update_all(del_flg: 1)

      redirect '/admin/banned', 302
    end
  end
end
