class PagesController < ApplicationController
  require "jwt"

def secured
  payload = decode_session_token
  if payload && has_role?(payload, "user")
    @user_info = payload
    render "secured"
  else
    render plain: "Unauthorized", status: :unauthorized
  end
end

def admin
  payload = decode_session_token
  if payload && has_role?(payload, "admin")
    @user_info = payload
    render "admin"
  else
    render plain: "Forbidden", status: :forbidden
  end
end


private

def decode_session_token
  token = session[:access_token]
  return nil unless token

  begin
    jwt_set = fetch_jwks # Load your cached JWKS or refetch if needed
    jwt_set.keys.each do |jwk|
      begin
        decoded = JWT.decode(token, jwk.public_key, true, algorithm: "RS256")
        return decoded.first # payload
      rescue JWT::DecodeError
        next
      end
    end
    nil
  rescue => e
    Rails.logger.warn "Failed to decode session token: #{e.message}"
    nil
  end
end

def has_role?(payload, role)
  roles = payload.dig("realm_access", "roles") || []
  roles.include?(role)
end

# Define fetch_jwks similarly to your middleware or use a shared module
def fetch_jwks
  uri = URI("#{ENV["KEYCLOAK_SITE"]}/realms/#{ENV["KEYCLOAK_REALM"]}/protocol/openid-connect/certs")
  response = Net::HTTP.get(uri)
  keys = JSON.parse(response)["keys"]
  JWT::JWK::Set.new(keys)
end
end
