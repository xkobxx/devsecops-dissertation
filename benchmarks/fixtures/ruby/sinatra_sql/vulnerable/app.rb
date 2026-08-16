# Deliberately vulnerable benchmark fixture. Do not deploy.
require "sinatra"
require "sqlite3"

get "/users" do
  database = SQLite3::Database.new("users.db")
  database.execute("SELECT * FROM users WHERE name = '#{params[:name]}'")
end
