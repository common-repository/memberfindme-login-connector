=== Plugin Name ===
Contributors: sourcefound
Donate link: https://membershipworks.com
Tags: membershipworks, memberfindme, membership management, membership, member login, billing, member access, member content
Requires at least: 4.0
Tested up to: 6.6.2
Stable tag: 6.4
License: GPL2
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Allows members to sign in to MembershipWorks and as a WordPress user on your site.

== Description ==

[MembershipWorks](https://membershipworks.com/) (formerly MemberFindMe) is a comprehensive website, membership management and event management solution for small to mid sized chambers, professional groups, associations and other member organizations.

This plugin supplements the main MembershipWorks plugin (version 5.0 and up) to allow your members signing in to MembershipWorks to be simultaneously signed in as a WordPress user. This lets you use other plugins that rely on the WordPress user system.

* Creates a new user account on WordPress (if account does not already exist) upon member login or signup
* Replaces Gravatar with the member's MembershipWorks avatar
* Adds a login/logout widget

== Installation ==

1. Install the plugin via the WordPress.org plugin directory or upload it to your plugins directory.
1. Activate the plugin

== Changelog ==

= 1.0 =
* Initial release

= 1.4 =
* Allows partial non-member access to protected pages/posts
* Improved handling of existing WordPress user accounts

= 1.6 =
* Allows restricting access by membership level or label

= 1.7 =
* Allows administrator to see member only content

= 1.8 =
* Improved handling of email conflicts

= 2.0 = 
* Allows members to request password
* No longer redirects members to WordPress login page if incorrect email or password is entered
* Adds nonmember-redirect option
* Adds nonmember option
* Adds message option
* Adds redirect option

= 2.1 =
* Adds support for redirect on logout
* Fixes issue with ajax login on some sites

= 2.2 =
* Prevents expired members from viewing member only content

= 2.3 =
* Adds supports member only content by folder

= 3.0 =
* Revamped login, does not use wp-login.php for maximum compatibility

= 3.0.1 =
* Fixes issue with header warning when user not signed in

= 3.0.2 =
* Fixes issue with header warning when user not signed in

= 3.0.3 =
* Fixes issue with MFM administrator being signed out

= 3.0.4 =
* Allows nonmember and nonmember-redirect options to work for signed in users

= 3.0.5 =
* Fixes compatibility with WordPress 4.0.1

= 3.1 =
* Improved compatibility with WordPress HTTPS

= 3.1.2 =
* Improved compatibility with site urls set to https

= 3.2 =
* Improves compatibility with WordPress 4.0.1

= 3.3 =
* Fixes some PHP warnings

= 3.4 =
* Sends nocache headers to prevent browser from loading member only pages or posts from cache when back button is used
* Fixes a PHP warning

= 3.5 =
* Fixes issue with WordPress 4.2.2 where user_nicename and display_name is not set when a duplicate email address exists in WP

= 3.6 =
* Can set content of Text widget to member only
* Adds nologin option

= 3.7 =
* Improved error messages

= 3.7.1 =
* Fixes bug with not fully logging out user when session expired

= 3.7.2 =
* Fixes issue with being unable to login if name update fails

= 3.8 =
* Fixes issue with username_exists

= 3.8.1 =
* Eliminates password changed email when logging in with WordPress 4.3

= 4.0 =
* Fixes PHP 5.3+ errors with deprecated function split
* Fixes warnings from ob_clean
* Updated API calls
* Displays appropriate message when member is not allowed access because of labels/folders vs. membership expiration

= 4.1 =
* Fixes issue with unicode quotation marks inside shortcode 

= 5.0 =
* MemberFindMe is now MembershipWorks!
* Moves member only content processing to main MembershipWorks plugin
* Accepts RETURN key to submit login form in widget
* Fixes some UX issues with widget

= 5.1 =
* Fixes login widget when logging into a existing WordPress user account without a MW account
* Provides option for using HTTP connection for customers running old versions of OpenSSL that do not support PCI compliant HTTPS connections

= 5.2 =
* Allow WordPress users to reset password with email address

= 5.3 =
* Fixes secure cookie issue over HTTPS

= 5.4 =
* Fixes conflicts for users resetting passwords for an exiting WP user

= 5.5 =
* Fixes bug for WP users logging in

= 5.6 =
* Fixes URL for avatars

= 5.7 =
* Tested for WP 5.0+

= 5.8 =
* Tesed for WP 5.1

= 6.0 =
* Fixes 400 error on logout

= 6.1 =
* Calls wp_destroy_current_session() on logout

= 6.2 =
* Logs out MW session when WP session expires

= 6.3 =
* Fixes issue where user sees session expired message after signing out via widget

= 6.4 =
* Provides compatibility with WooCommerce login form