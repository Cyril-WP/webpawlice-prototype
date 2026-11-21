<?php
/**
 * Plugin Name: WebPawlice (PROTOTYPE)
 * Description: Adds the WebPawlice check-up to this site. Visitors see nothing; logged-in administrators get the blue paw on every page. Throwaway prototype by Webpuppies.
 * Version: 0.1.0
 *
 * Install: copy to wp-content/mu-plugins/webpawlice.php. No settings.
 */

defined( 'ABSPATH' ) || exit;

add_action(
	'wp_footer',
	function () {
		// Admins see the paw everywhere; everyone else gets the inert script (it only wakes on ?webpawlice).
		$show = current_user_can( 'manage_options' ) ? ' data-show="always"' : '';
		echo '<script src="https://cyril-wp.github.io/webpawlice-prototype/embed/webpawlice.js" defer' . $show . "></script>\n"; // phpcs:ignore WordPress.WP.EnqueuedResources
	}
);
