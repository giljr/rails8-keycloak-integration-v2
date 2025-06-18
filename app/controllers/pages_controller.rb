class PagesController < ApplicationController
  require "jwt"
  require "net/http"
  require "json"

  REALM = ENV.fetch("KEYCLOAK_REALM")
  SITE  = ENV.fetch("KEYCLOAK_SITE")

  def secured
    payload = decode_token
    if payload && has_role?(payload, "user")
      @user_info = payload
      render "secured"
    else
      render plain: "Unauthorized", status: :unauthorized
    end
  end

  def admin
    payload = decode_token
    if payload && has_role?(payload, "admin")
      @user_info = payload
      render "admin"
    else
      render plain: "Forbidden", status: :forbidden
    end
  end

  private

  def decode_token
    token = token_from_header || session[:access_token]
    return nil unless token

    fetch_jwks.keys.each do |jwk|
      begin
        decoded = JWT.decode(token, jwk.public_key, true, algorithm: "RS256")
        return decoded.first
      rescue JWT::DecodeError
        next
      end
    end
    nil
  rescue => e
    Rails.logger.warn "JWT decode error: #{e.message}"
    nil
  end

  def token_from_header
    auth = request.get_header("HTTP_AUTHORIZATION")
    auth&.start_with?("Bearer ") && auth.split.last
  end

  def has_role?(payload, role)
    roles = payload.dig("realm_access", "roles") || []
    Rails.logger.debug "Checking role '#{role}' in #{roles.inspect}"
    roles.include?(role)
  end

  def fetch_jwks
    uri = URI("#{SITE}/realms/#{REALM}/protocol/openid-connect/certs")
    keys = JSON.parse(Net::HTTP.get_response(uri).body)["keys"]
    JWT::JWK::Set.new(keys)
  rescue
    Rails.logger.warn "Failed to fetch JWKS"
    JWT::JWK::Set.new([])
  end
end
class PagesController < ApplicationController
  require "jwt"
  require "net/http"
  require "json"

  REALM = ENV.fetch("KEYCLOAK_REALM")
  SITE  = ENV.fetch("KEYCLOAK_SITE")

  def secured
    payload = decode_token
    if payload && has_role?(payload, "user")
      @user_info = payload
      render "secured"
    else
      render plain: "Unauthorized", status: :unauthorized
    end
  end

  def admin
    payload = decode_token
    if payload && has_role?(payload, "admin")
      @user_info = payload
      render "admin"
    else
      render plain: "Forbidden", status: :forbidden
    end
  end

  private

  def decode_token
    token = token_from_header || session[:access_token]
    return nil unless token

    fetch_jwks.keys.each do |jwk|
      begin
        decoded = JWT.decode(token, jwk.public_key, true, algorithm: "RS256")
        return decoded.first
      rescue JWT::DecodeError
        next
      end
    end
    nil
  rescue => e
    Rails.logger.warn "JWT decode error: #{e.message}"
    nil
  end

  def token_from_header
    auth = request.get_header("HTTP_AUTHORIZATION")
    auth&.start_with?("Bearer ") && auth.split.last
  end

  def has_role?(payload, role)
    roles = payload.dig("realm_access", "roles") || []
    Rails.logger.debug "Checking role '#{role}' in #{roles.inspect}"
    roles.include?(role)
  end

  def fetch_jwks
    uri = URI("#{SITE}/realms/#{REALM}/protocol/openid-connect/certs")
    keys = JSON.parse(Net::HTTP.get_response(uri).body)["keys"]
    JWT::JWK::Set.new(keys)
  rescue
    Rails.logger.warn "Failed to fetch JWKS"
    JWT::JWK::Set.new([])
  end
end
