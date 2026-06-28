<?php
/*
Plugin Name: Domain Allowlist + Alerts
Plugin URI: https://github.com/seventhsite/yourls-domain-allowlist
Description: Restrict URL shortening to an allowlist of domains, with an admin settings page (edit the list, one-click-allow rejected domains, manage Telegram alerts) and optional throttled Telegram alerts about rejected domains. Self-contained: no extra DB table, no cron, no server tweaks — a bounded JSON file plus a traffic-driven "lazy cron" digest. Config is drop-in compatible with nicwaller/yourls-domainlimit ($domainlimit_list / $domainlimit_exempt_users).
Version: 1.0.0
Author: seventhsite
Author URI: https://github.com/seventhsite
License: GPL-2.0-or-later
*/

// No direct call.
if ( ! defined( 'YOURLS_ABSPATH' ) ) {
	die();
}

// Admin-managed stores (DB options). The allowlist BASE stays in config.php
// ($domainlimit_list); these are the GUI additions/settings layered on top.
const DA_OPT_EXTRA    = 'domain_allowlist_extra';    // array of admin-added domains
const DA_OPT_SETTINGS = 'domain_allowlist_settings'; // array of admin-managed alert settings

// ---------------------------------------------------------------------------
// Configuration — config.php is authoritative; the admin DB option is the
// fallback for installs that prefer the GUI. (See README for precedence.)
// ---------------------------------------------------------------------------

function da_config() {
	global $domain_allowlist_message, $domain_allowlist_alerts;

	$opt = yourls_get_option( DA_OPT_SETTINGS, array() );
	if ( ! is_array( $opt ) ) {
		$opt = array();
	}

	// Alerts: a config array wins wholesale if present; otherwise the admin option.
	$alerts_from_config = is_array( $domain_allowlist_alerts ?? null );
	$a = $alerts_from_config ? $domain_allowlist_alerts : $opt;

	// Message: config global wins, else admin option, else a generic default.
	$message_from_config = is_string( $domain_allowlist_message ?? null ) && $domain_allowlist_message !== '';
	if ( $message_from_config ) {
		$message = $domain_allowlist_message;
	} elseif ( is_string( $opt['message'] ?? null ) && $opt['message'] !== '' ) {
		$message = $opt['message'];
	} else {
		$message = "Sorry, links to that domain can't be shortened here.";
	}

	return array(
		'message' => $message,

		// Telegram alerting.
		'token'   => (string) ( $a['telegram_token'] ?? '' ),
		'chat'    => (string) ( $a['telegram_chat']  ?? '' ),
		'mode'    => in_array( $a['mode'] ?? 'off', array( 'instant', 'digest', 'both', 'off' ), true )
			? $a['mode'] : 'off',

		// Anti-spam / anti-ban throttling (seconds).
		'per_domain_cooldown' => (int) ( $a['per_domain_cooldown'] ?? 21600 ), // 6h: re-alert same host
		'global_min_gap'      => (int) ( $a['global_min_gap']      ?? 30 ),    // 30s: gap between any sends
		'digest_interval'     => (int) ( $a['digest_interval']     ?? 86400 ), // 24h: lazy-cron cadence

		// Storage bounds / location.
		'max_hosts'  => max( 10, (int) ( $a['max_hosts'] ?? 200 ) ), // hard cap → file size is bounded
		'store_path' => (string) ( $a['store_path'] ?? '' ),         // '' = auto (plugin data/ → temp)

		// Meta for the admin UI (where each setting is sourced from).
		'alerts_from_config'  => $alerts_from_config,
		'message_from_config' => $message_from_config,
	);
}

/** True when Telegram is configured and alerting isn't switched off. */
function da_alerts_ready( $cfg ) {
	return $cfg['mode'] !== 'off' && $cfg['token'] !== '' && $cfg['chat'] !== '';
}

// ---------------------------------------------------------------------------
// Allowlist resolution: config base ∪ admin-managed extras (model A)
// ---------------------------------------------------------------------------

/** The config.php base list ($domainlimit_list), normalised to an array. */
function da_config_domains() {
	global $domainlimit_list;
	if ( ! isset( $domainlimit_list ) ) {
		return array();
	}
	return is_array( $domainlimit_list ) ? array_values( $domainlimit_list ) : array( (string) $domainlimit_list );
}

/** Admin-added domains from the DB option. */
function da_extra_domains() {
	$v = yourls_get_option( DA_OPT_EXTRA, array() );
	return is_array( $v ) ? array_values( $v ) : array();
}

/** Effective allowlist = config base ∪ admin extras (lowercased, de-duplicated). */
function da_allowed_list() {
	$out = array();
	foreach ( array_merge( da_config_domains(), da_extra_domains() ) as $d ) {
		$d = strtolower( trim( (string) $d ) );
		if ( $d !== '' ) {
			$out[ $d ] = true; // dedupe via keys
		}
	}
	return array_keys( $out );
}

// ---------------------------------------------------------------------------
// The gate: block links whose host isn't on the effective allowlist
// ---------------------------------------------------------------------------

yourls_add_filter( 'shunt_add_new_link', 'da_shunt_add_new_link', 10, 4 );

function da_shunt_add_new_link( $return, $url, $keyword = '', $title = '' ) {
	global $domainlimit_exempt_users;

	$list = da_allowed_list();
	if ( ! $list ) {
		// Nothing configured anywhere → fail closed (don't silently allow all).
		return array(
			'status'    => 'fail',
			'code'      => 'error:configuration',
			'message'   => 'Domain allowlist is empty — set $domainlimit_list in config.php or add domains on the plugin settings page.',
			'errorCode' => '500',
		);
	}

	// Logged-in operators listed as exempt bypass the check entirely.
	$user = defined( 'YOURLS_USER' ) ? YOURLS_USER : '';
	if ( is_array( $domainlimit_exempt_users ?? null ) && in_array( $user, $domainlimit_exempt_users, true ) ) {
		return $return;
	}

	// yourls_escape / yourls_encodeURI are deprecated and unnecessary for host
	// extraction; sanitize is enough and stays quiet on modern PHP.
	$url = yourls_sanitize_url( $url );
	if ( ! $url || $url === 'http://' || $url === 'https://' ) {
		$r = array(
			'status'    => 'fail',
			'code'      => 'error:nourl',
			'message'   => yourls__( 'Missing or malformed URL' ),
			'errorCode' => '400',
		);
		return yourls_apply_filter( 'add_new_link_fail_nourl', $r, $url, $keyword, $title );
	}

	$host = parse_url( $url, PHP_URL_HOST );

	if ( da_host_allowed( $host, $list ) ) {
		return $return; // pass through to core link creation
	}

	// --- Rejected. Record + (maybe) alert, then return a structured error. ---
	da_handle_rejection( $host ); // best-effort, never throws

	$cfg = da_config();
	return array(
		'status'          => 'fail',
		'code'            => 'error:disallowedhost',
		'message'         => $cfg['message'],
		'errorCode'       => '400',
		// Structured extras so a theme can render a nice error; ignored by core.
		'disallowed_host' => is_string( $host ) ? $host : '',
		'allowed_domains' => $list,
	);
}

// ---------------------------------------------------------------------------
// Host matching (suffix match; "notunbc.ca" is NOT a subdomain of "unbc.ca")
// ---------------------------------------------------------------------------

function da_host_allowed( $host, $list ) {
	if ( ! is_string( $host ) || $host === '' ) {
		return false; // no parseable host → not allowed (and null-safe on PHP 8.5)
	}
	$host = strtolower( $host );
	foreach ( $list as $allowed ) {
		$allowed = strtolower( (string) $allowed );
		if ( $allowed === '' ) {
			continue;
		}
		if ( $host === $allowed ) {
			return true;
		}
		$suffix = '.' . ltrim( $allowed, '.' );
		if ( substr( $host, -strlen( $suffix ) ) === $suffix ) {
			return true; // exact subdomain match
		}
	}
	return false;
}

// ---------------------------------------------------------------------------
// Rejection handling: bounded file storage + throttled Telegram + lazy digest
// ---------------------------------------------------------------------------

/**
 * Record a rejected host and decide what to send, all under one file lock.
 * Network I/O happens AFTER the lock is released so a slow Telegram call never
 * blocks other shorten requests. Entirely best-effort: any failure is swallowed.
 */
function da_handle_rejection( $host ) {
	if ( ! is_string( $host ) || $host === '' ) {
		return;
	}
	$cfg = da_config();
	if ( ! da_alerts_ready( $cfg ) ) {
		return; // nothing to do if alerting is off / unconfigured
	}

	$path = da_store_path( $cfg );
	if ( ! $path ) {
		// No writable storage → we can't throttle across requests, so sending
		// would risk spam/bans. Fail safe (silent) + a one-time admin notice.
		da_admin_notice_once();
		return;
	}

	$now = time();
	$actions = da_store_mutate( $path, function ( array &$s ) use ( $host, $now, $cfg ) {
		// Upsert the host record.
		$rec = $s['rejects'][ $host ] ?? array( 'hits' => 0, 'first' => $now, 'last' => $now, 'notified' => 0 );
		$rec['hits']++;
		$rec['last'] = $now;
		$s['rejects'][ $host ] = $rec;

		// Bound the buffer: evict least-recently-seen beyond the cap → fixed size.
		if ( count( $s['rejects'] ) > $cfg['max_hosts'] ) {
			uasort( $s['rejects'], fn( $a, $b ) => $a['last'] <=> $b['last'] );
			$s['rejects'] = array_slice( $s['rejects'], -$cfg['max_hosts'], null, true );
		}

		$send_instant = false;
		$send_digest  = false;

		if ( in_array( $cfg['mode'], array( 'instant', 'both' ), true ) ) {
			$cooldown_ok = ( $now - (int) $s['rejects'][ $host ]['notified'] ) >= $cfg['per_domain_cooldown'];
			$gap_ok      = ( $now - (int) ( $s['global_last_notify'] ?? 0 ) ) >= $cfg['global_min_gap'];
			if ( $cooldown_ok && $gap_ok ) {
				$send_instant = true;
				$s['rejects'][ $host ]['notified'] = $now;
				$s['global_last_notify']           = $now;
			}
		}

		if ( in_array( $cfg['mode'], array( 'digest', 'both' ), true ) ) {
			if ( ( $now - (int) ( $s['last_digest'] ?? 0 ) ) >= $cfg['digest_interval'] ) {
				$send_digest      = true;
				$s['last_digest'] = $now;
			}
		}

		// Snapshot for the digest (top hosts by hits) while we hold the lock.
		$top = $s['rejects'];
		uasort( $top, fn( $a, $b ) => $b['hits'] <=> $a['hits'] );
		$top = array_slice( $top, 0, 10, true );

		return array(
			'instant'  => $send_instant ? array( 'host' => $host, 'hits' => $s['rejects'][ $host ]['hits'] ) : null,
			'digest'   => $send_digest ? $top : null,
			'distinct' => count( $s['rejects'] ),
		);
	} );

	if ( ! is_array( $actions ) ) {
		return; // storage unavailable this time
	}

	// --- Network sends, outside the lock ---
	$site = da_site_label();
	if ( $actions['instant'] ) {
		da_telegram_send(
			$cfg,
			"🔗 <b>" . da_h( $site ) . "</b> — new blocked domain\n"
			. "<code>" . da_h( $actions['instant']['host'] ) . "</code>\n"
			. "Someone tried to shorten it (×" . (int) $actions['instant']['hits'] . "). "
			. "Add it to the allowlist if it's a legit store."
		);
	}
	if ( $actions['digest'] ) {
		$lines = array( "📊 <b>" . da_h( $site ) . "</b> — top blocked domains" );
		foreach ( $actions['digest'] as $h => $rec ) {
			$lines[] = (int) $rec['hits'] . "× <code>" . da_h( $h ) . "</code>";
		}
		$lines[] = "\n" . (int) $actions['distinct'] . " distinct domain(s) tracked.";
		da_telegram_send( $cfg, implode( "\n", $lines ) );
	}
}

/** Remove hosts from the rejects buffer (used after allow / dismiss). */
function da_store_remove( array $hosts ) {
	$path = da_store_path( da_config() );
	if ( ! $path ) {
		return;
	}
	da_store_mutate( $path, function ( array &$s ) use ( $hosts ) {
		foreach ( $hosts as $h ) {
			unset( $s['rejects'][ strtolower( $h ) ] );
		}
		return true;
	} );
}

/** Read the rejects buffer for display (read-only, no lock). host => record. */
function da_store_read() {
	$path = da_store_path( da_config() );
	if ( ! $path || ! is_file( $path ) ) {
		return array();
	}
	$s = json_decode( (string) @file_get_contents( $path ), true );
	return is_array( $s['rejects'] ?? null ) ? $s['rejects'] : array();
}

/** Resolve the storage file path: plugin data/ if writable, else system temp. */
function da_store_path( $cfg ) {
	if ( $cfg['store_path'] !== '' ) {
		return $cfg['store_path'];
	}
	$dir = __DIR__ . '/data';
	if ( ! is_dir( $dir ) ) {
		@mkdir( $dir, 0775, true );
	}
	if ( is_dir( $dir ) && is_writable( $dir ) ) {
		return $dir . '/rejects.json';
	}
	$tmp = rtrim( sys_get_temp_dir(), '/\\' );
	if ( $tmp && is_writable( $tmp ) ) {
		// Per-site file so sites sharing a temp dir don't collide.
		$key = substr( md5( defined( 'YOURLS_SITE' ) ? YOURLS_SITE : __DIR__ ), 0, 12 );
		return $tmp . '/yourls-domain-allowlist-' . $key . '.json';
	}
	return ''; // no writable location
}

/**
 * Lock the store, hand the decoded state to $mutator (by reference), persist the
 * result, return whatever $mutator returned. Returns null if the file can't be
 * opened/locked. Network must NOT be done inside $mutator.
 */
function da_store_mutate( $path, callable $mutator ) {
	$fh = @fopen( $path, 'c+' );
	if ( ! $fh ) {
		return null;
	}
	try {
		if ( ! flock( $fh, LOCK_EX ) ) {
			return null;
		}
		$raw   = stream_get_contents( $fh );
		$state = json_decode( $raw, true );
		if ( ! is_array( $state ) ) {
			$state = array( 'rejects' => array(), 'last_digest' => 0, 'global_last_notify' => 0 );
		}
		if ( ! isset( $state['rejects'] ) || ! is_array( $state['rejects'] ) ) {
			$state['rejects'] = array();
		}

		$result = $mutator( $state );

		rewind( $fh );
		ftruncate( $fh, 0 );
		fwrite( $fh, json_encode( $state ) );
		fflush( $fh );
		flock( $fh, LOCK_UN );
		return $result;
	} finally {
		fclose( $fh );
	}
}

/** Send one Telegram message. Short timeout, never throws. Returns success bool. */
function da_telegram_send( $cfg, $text ) {
	if ( $cfg['token'] === '' || $cfg['chat'] === '' ) {
		return false;
	}
	$url  = "https://api.telegram.org/bot{$cfg['token']}/sendMessage";
	$data = http_build_query( array(
		'chat_id'                  => $cfg['chat'],
		'text'                     => $text,
		'parse_mode'               => 'HTML',
		'disable_web_page_preview' => 'true',
	) );

	try {
		if ( function_exists( 'curl_init' ) ) {
			$ch = curl_init( $url );
			curl_setopt_array( $ch, array(
				CURLOPT_POST           => true,
				CURLOPT_POSTFIELDS     => $data,
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_TIMEOUT        => 4,        // hard cap so the request can't hang
				CURLOPT_CONNECTTIMEOUT => 3,
			) );
			$res  = curl_exec( $ch );
			$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
			curl_close( $ch );
			return $res !== false && $code >= 200 && $code < 300;
		}
		$ctx = stream_context_create( array( 'http' => array(
			'method'        => 'POST',
			'header'        => 'Content-Type: application/x-www-form-urlencoded',
			'content'       => $data,
			'timeout'       => 4,
			'ignore_errors' => true,
		) ) );
		return @file_get_contents( $url, false, $ctx ) !== false;
	} catch ( \Throwable $e ) {
		return false; // an alert failure must never affect the caller
	}
}

/** Best-effort host label for messages, e.g. "ali.onl". */
function da_site_label() {
	$h = parse_url( defined( 'YOURLS_SITE' ) ? YOURLS_SITE : '', PHP_URL_HOST );
	return $h ?: 'YOURLS';
}

/** HTML-escape for the (HTML parse_mode) Telegram payload. */
function da_h( $s ) {
	return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' );
}

/** One-time admin-area notice when storage isn't writable. */
function da_admin_notice_once() {
	if ( ! yourls_is_admin() ) {
		return;
	}
	static $done = false;
	if ( $done ) {
		return;
	}
	$done = true;
	yourls_add_notice(
		'Domain Allowlist: no writable storage for alert throttling — Telegram alerts are disabled. '
		. 'Make the plugin <code>data/</code> dir or the system temp dir writable, or set <code>store_path</code>.'
	);
}

// ---------------------------------------------------------------------------
// Admin settings page
// ---------------------------------------------------------------------------

yourls_register_plugin_page( 'domain_allowlist', 'Domain Allowlist', 'da_admin_page' );

/** Parse a textarea/CSV blob into a clean, de-duplicated list of bare hosts. */
function da_sanitize_domains( $text ) {
	$out = array();
	foreach ( preg_split( '/[\r\n,]+/', (string) $text ) as $line ) {
		$d = strtolower( trim( $line ) );
		if ( $d === '' ) {
			continue;
		}
		// If a full URL was pasted, keep only the host.
		if ( strpos( $d, '/' ) !== false || strpos( $d, ':' ) !== false ) {
			$h = parse_url( strpos( $d, '://' ) === false ? 'http://' . $d : $d, PHP_URL_HOST );
			if ( is_string( $h ) && $h !== '' ) {
				$d = $h;
			}
		}
		$d = ltrim( $d, '.' );
		if ( strpos( $d, '*.' ) === 0 ) {
			$d = substr( $d, 2 ); // "*.example.com" → "example.com" (subdomains already match)
		}
		$d = preg_replace( '/[^a-z0-9.\-]/', '', $d ); // host chars only
		if ( $d !== '' ) {
			$out[ $d ] = true;
		}
	}
	return array_keys( $out );
}

/** Storage status for the admin page. */
function da_store_meta() {
	$path = da_store_path( da_config() );
	$s    = ( $path && is_file( $path ) ) ? json_decode( (string) @file_get_contents( $path ), true ) : array();
	if ( ! is_array( $s ) ) {
		$s = array();
	}
	$rej = is_array( $s['rejects'] ?? null ) ? $s['rejects'] : array();
	return array(
		'path'        => $path,
		'writable'    => $path ? ( is_file( $path ) ? is_writable( $path ) : is_writable( dirname( $path ) ) ) : false,
		'distinct'    => count( $rej ),
		'last_digest' => (int) ( $s['last_digest'] ?? 0 ),
	);
}

function da_admin_page() {
	$nonce  = 'domain_allowlist';
	$notices = array();

	// ---- Handle POST actions ----
	if ( isset( $_POST['da_action'] ) ) {
		yourls_verify_nonce( $nonce );
		$cfg = da_config();
		$act = $_POST['da_action'];

		if ( $act === 'save_list' ) {
			$clean = da_sanitize_domains( $_POST['da_extra'] ?? '' );
			yourls_update_option( DA_OPT_EXTRA, $clean );
			$notices[] = 'Saved ' . count( $clean ) . ' additional domain(s).';

		} elseif ( $act === 'allow' ) {
			$add = da_sanitize_domains( $_POST['domain'] ?? '' );
			if ( $add ) {
				$extra = array_values( array_unique( array_merge( da_extra_domains(), $add ) ) );
				yourls_update_option( DA_OPT_EXTRA, $extra );
				da_store_remove( $add );
				$notices[] = 'Added to allowlist: ' . implode( ', ', $add );
			}

		} elseif ( $act === 'dismiss' ) {
			$rm = da_sanitize_domains( $_POST['domain'] ?? '' );
			if ( $rm ) {
				da_store_remove( $rm );
				$notices[] = 'Dismissed: ' . implode( ', ', $rm );
			}

		} elseif ( $act === 'save_alerts' ) {
			if ( $cfg['alerts_from_config'] ) {
				$notices[] = 'Alerts are managed in config.php — not editable here.';
			} else {
				$settings = array(
					'telegram_token'      => trim( (string) ( $_POST['token'] ?? '' ) ),
					'telegram_chat'       => trim( (string) ( $_POST['chat'] ?? '' ) ),
					'mode'                => in_array( $_POST['mode'] ?? 'off', array( 'instant', 'digest', 'both', 'off' ), true ) ? $_POST['mode'] : 'off',
					'message'             => trim( (string) ( $_POST['message'] ?? '' ) ),
					'per_domain_cooldown' => max( 0, (int) ( $_POST['per_domain_cooldown'] ?? 21600 ) ),
					'global_min_gap'      => max( 0, (int) ( $_POST['global_min_gap'] ?? 30 ) ),
					'digest_interval'     => max( 60, (int) ( $_POST['digest_interval'] ?? 86400 ) ),
					'max_hosts'           => max( 10, (int) ( $_POST['max_hosts'] ?? 200 ) ),
				);
				yourls_update_option( DA_OPT_SETTINGS, $settings );
				$notices[] = 'Alert settings saved.';
			}

		} elseif ( $act === 'send_test' ) {
			$cfg = da_config(); // refresh after any save above
			if ( $cfg['token'] === '' || $cfg['chat'] === '' ) {
				$notices[] = 'Set a Telegram token and chat id first.';
			} else {
				$ok = da_telegram_send( $cfg, '✅ <b>' . da_h( da_site_label() ) . '</b> — Domain Allowlist test message.' );
				$notices[] = $ok ? 'Test message sent.' : 'Test message FAILED (check token/chat and connectivity).';
			}
		}
	}

	// ---- Render ----
	$cfg       = da_config();
	$cfgDoms   = da_config_domains();
	$extra     = da_extra_domains();
	$effective = da_allowed_list();
	$meta      = da_store_meta();

	echo '<h2>Domain Allowlist + Alerts</h2>';
	foreach ( $notices as $n ) {
		echo '<p style="padding:8px 12px;background:#eef7ff;border:1px solid #cfe3f5;border-radius:6px;"><strong>' . yourls_esc_html( $n ) . '</strong></p>';
	}

	// --- Allowed domains ---
	echo '<h3>Allowed domains</h3>';
	echo '<p>Effective list: <strong>' . count( $effective ) . '</strong> domain(s) — '
		. count( $cfgDoms ) . ' from <code>config.php</code> + ' . count( $extra ) . ' added here.</p>';
	if ( $cfgDoms ) {
		echo '<details><summary>' . count( $cfgDoms ) . ' base domain(s) from config.php (read-only)</summary>'
			. '<p style="font-family:monospace;font-size:12px;color:#555;">' . yourls_esc_html( implode( ', ', $cfgDoms ) ) . '</p></details>';
	}
	echo '<form method="post">';
	yourls_nonce_field( $nonce );
	echo '<input type="hidden" name="da_action" value="save_list">';
	echo '<p>Additional domains, one per line (stored in the database, editable here):</p>';
	echo '<textarea name="da_extra" rows="6" style="width:100%;max-width:560px;font-family:monospace;">'
		. yourls_esc_html( implode( "\n", $extra ) ) . '</textarea><br>';
	echo '<p><button class="button" type="submit">Save list</button></p>';
	echo '</form>';

	// --- Rejected domains (one-click allow) ---
	$rej = da_store_read();
	uasort( $rej, fn( $a, $b ) => ( $b['hits'] ?? 0 ) <=> ( $a['hits'] ?? 0 ) );
	echo '<h3>Rejected domains <span style="color:#888;font-weight:normal;">(' . count( $rej ) . ' tracked)</span></h3>';
	echo '<p style="color:#666;">Domains users tried to shorten but that aren\'t allowed. Add legit stores with one click.</p>';
	if ( ! $rej ) {
		echo '<p><em>None recorded yet.</em></p>';
	} else {
		echo '<table cellpadding="6" style="border-collapse:collapse;width:100%;max-width:680px;">';
		echo '<tr style="text-align:left;border-bottom:2px solid #ddd;"><th>Domain</th><th>Hits</th><th>Last seen</th><th></th></tr>';
		$i = 0;
		foreach ( $rej as $host => $rec ) {
			if ( $i++ >= 100 ) {
				break;
			}
			echo '<tr style="border-bottom:1px solid #eee;">';
			echo '<td><code>' . yourls_esc_html( $host ) . '</code></td>';
			echo '<td align="center">' . (int) ( $rec['hits'] ?? 0 ) . '</td>';
			echo '<td>' . yourls_esc_html( date( 'Y-m-d H:i', (int) ( $rec['last'] ?? 0 ) ) ) . '</td>';
			echo '<td style="white-space:nowrap;">';
			foreach ( array( 'allow' => 'Add to allowlist', 'dismiss' => 'Dismiss' ) as $a => $label ) {
				echo '<form method="post" style="display:inline;margin-right:4px;">';
				yourls_nonce_field( $nonce );
				echo '<input type="hidden" name="da_action" value="' . $a . '">';
				echo '<input type="hidden" name="domain" value="' . yourls_esc_attr( $host ) . '">';
				echo '<button class="button" type="submit">' . $label . '</button>';
				echo '</form>';
			}
			echo '</td></tr>';
		}
		echo '</table>';
	}

	// --- Telegram alerts ---
	echo '<h3>Telegram alerts</h3>';
	if ( $cfg['alerts_from_config'] ) {
		echo '<p><em>Managed in <code>config.php</code> (<code>$domain_allowlist_alerts</code>) — read-only here.</em></p>';
		echo '<ul>';
		echo '<li>Mode: <code>' . yourls_esc_html( $cfg['mode'] ) . '</code></li>';
		echo '<li>Token: <code>' . ( $cfg['token'] !== '' ? 'set' : '—' ) . '</code>, Chat: <code>' . ( $cfg['chat'] !== '' ? 'set' : '—' ) . '</code></li>';
		echo '</ul>';
	} else {
		echo '<form method="post">';
		yourls_nonce_field( $nonce );
		echo '<input type="hidden" name="da_action" value="save_alerts">';
		echo '<table cellpadding="4">';
		echo '<tr><td>Mode</td><td><select name="mode">';
		foreach ( array( 'off', 'instant', 'digest', 'both' ) as $m ) {
			echo '<option value="' . $m . '"' . ( $cfg['mode'] === $m ? ' selected' : '' ) . '>' . $m . '</option>';
		}
		echo '</select></td></tr>';
		echo '<tr><td>Bot token</td><td><input type="text" name="token" size="50" value="' . yourls_esc_attr( $cfg['token'] ) . '"></td></tr>';
		echo '<tr><td>Chat id</td><td><input type="text" name="chat" size="24" value="' . yourls_esc_attr( $cfg['chat'] ) . '"></td></tr>';
		echo '<tr><td>Reject message</td><td><input type="text" name="message" size="60" value="' . yourls_esc_attr( $cfg['message_from_config'] ? '' : $cfg['message'] ) . '"></td></tr>';
		echo '<tr><td>Per-domain cooldown (s)</td><td><input type="number" name="per_domain_cooldown" value="' . (int) $cfg['per_domain_cooldown'] . '"></td></tr>';
		echo '<tr><td>Global min gap (s)</td><td><input type="number" name="global_min_gap" value="' . (int) $cfg['global_min_gap'] . '"></td></tr>';
		echo '<tr><td>Digest interval (s)</td><td><input type="number" name="digest_interval" value="' . (int) $cfg['digest_interval'] . '"></td></tr>';
		echo '<tr><td>Max tracked domains</td><td><input type="number" name="max_hosts" value="' . (int) $cfg['max_hosts'] . '"></td></tr>';
		echo '</table>';
		echo '<p><button class="button" type="submit">Save alert settings</button></p>';
		echo '</form>';
	}
	echo '<form method="post" style="margin-top:6px;">';
	yourls_nonce_field( $nonce );
	echo '<input type="hidden" name="da_action" value="send_test">';
	echo '<button class="button" type="submit">Send test message</button> ';
	echo '<span style="color:#888;">— posts a test alert to the configured chat.</span>';
	echo '</form>';

	// --- Status ---
	echo '<h3>Status</h3><ul>';
	echo '<li>Alert mode: <code>' . yourls_esc_html( $cfg['mode'] ) . '</code> (' . ( $cfg['alerts_from_config'] ? 'config' : 'admin' ) . '-managed)</li>';
	echo '<li>Distinct domains tracked: ' . (int) $meta['distinct'] . ' / cap ' . (int) $cfg['max_hosts'] . '</li>';
	$digest_used = in_array( $cfg['mode'], array( 'digest', 'both' ), true );
	echo '<li>Last digest: ' . ( ! $digest_used
		? 'n/a (mode is <code>' . yourls_esc_html( $cfg['mode'] ) . '</code> — no digest)'
		: ( $meta['last_digest'] ? yourls_esc_html( date( 'Y-m-d H:i', $meta['last_digest'] ) ) : 'never yet' ) ) . '</li>';
	echo '<li>Storage file: <code>' . yourls_esc_html( $meta['path'] ?: '(none writable!)' ) . '</code>'
		. ( $meta['writable'] ? '' : ' <strong style="color:#b00;">— NOT writable, alerts disabled</strong>' ) . '</li>';
	echo '</ul>';
}
