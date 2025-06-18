class SessionsController < ApplicationController
  def callback
    code = params[:code]
    state = params[:state]

    unless code
      redirect_to root_path, alert: "Authorization code missing" and return
    end

    token_response = exchange_code_for_token(code)

    if token_response && token_response["access_token"]
      session[:access_token] = token_response["access_token"]
      session[:userinfo] = decode_token(token_response["access_token"])
      redirect_to secured_path, notice: "Logged in!"
    else
      redirect_to root_path, alert: "Failed to obtain token"
    end
  end

  private

  def exchange_code_for_token(code)
    uri = URI("http://localhost:8080/realms/quickstart/protocol/openid-connect/token")
    res = Net::HTTP.post_form(uri, {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: "http://localhost:3000/auth/callback",
      client_id: "test-cli"
      # Add `client_secret:` if needed
    })
    JSON.parse(res.body)
  rescue => e
    Rails.logger.error("Token exchange failed: #{e}")
    nil
  end

  def decode_token(token)
    JWT.decode(token, nil, false).first
  rescue => e
    Rails.logger.error("Token decode failed: #{e}")
    {}
  end
end
