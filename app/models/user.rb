class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,
		 :confirmable, :lockable, :omniauthable, omniauth_providers: [:google_oauth2]
  protected
  def self.find_for_google(auth)
    user = User.find_by(email: auth['info']['email'])
    unless user
      user = User.create(email: auth['info']['email'],
                         provider: auth['provider'],
                         uid:      auth['uid'],
                         token:    auth['credentials']['token'],
                         password: Devise.friendly_token[0, 20],
                         meta:     auth['to_yaml'])
	  user.skip_confirmation!
	  user.save!
    end
    user
  end
end
