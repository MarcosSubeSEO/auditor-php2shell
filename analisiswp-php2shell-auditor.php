<?php
/**
 * Plugin Name: AnalisisWP - Auditor PHP2Shell
 * Description: Comprueba la version de PHP y busca indicadores locales de compromiso. Auditoria de solo lectura, sin garantizar ausencia de intrusiones.
 * Version: 1.6.0
 * Requires PHP: 7.4
 * Author: AnalisisWP
 * License: GPL-2.0-or-later
 */
if (!defined('ABSPATH')) { exit; }
final class AWP_PHP2Shell_Auditor {
    const SLUG = 'awp-php2shell-auditor';
    const NONCE = 'awp_php2shell_scan';
    const SETTINGS_NONCE = 'awp_php2shell_logs_settings';
    const LOGS_OPTION = 'awp_php2shell_log_paths';
    const TRANSIENT_PREFIX = 'awp_php2shell_report_';
    const MAX_FILES = 12000;
    const MAX_SECONDS = 12;
    const MAX_FILE_SIZE = 1048576;
    const MAX_LOG_BYTES = 2097152;
    const MAX_LOG_LINES = 3500;
    private static $fixed = array('8.2'=>'8.2.35','8.3'=>'8.3.36','8.4'=>'8.4.27','8.5'=>'8.5.12');
    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'menu'));
        add_action('admin_post_awp_php2shell_scan', array(__CLASS__, 'run'));
        add_action('admin_post_awp_php2shell_save_logs', array(__CLASS__, 'save_logs'));
    }
    public static function menu() {
        add_management_page('Auditor PHP2Shell', 'Auditor PHP2Shell', 'manage_options', self::SLUG, array(__CLASS__, 'page'));
    }
    private static function esc($value) { return esc_html((string)$value); }
    private static function status() {
        $version = PHP_VERSION;
        $branch = PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;
        if (isset(self::$fixed[$branch])) {
            return array('version'=>$version,'branch'=>$branch,'fixed'=>self::$fixed[$branch], 'state'=>version_compare($version, self::$fixed[$branch], '>=') ? 'corrected' : 'potential',
                'note'=>'Comparacion por numero de version. Un proveedor puede haber aplicado parches retroportados; confirme con el hosting.');
        }
        if (version_compare($version, '8.2', '<')) {
            return array('version'=>$version,'branch'=>$branch,'fixed'=>'—','state'=>'unsupported','note'=>'Rama antigua sin soporte general del proyecto PHP. Compruebe soporte extendido y parches del proveedor.');
        }
        return array('version'=>$version,'branch'=>$branch,'fixed'=>'—','state'=>'unknown','note'=>'Esta rama no esta incluida en las referencias configuradas. Verifique los avisos de seguridad oficiales.');
    }
    private static function add(&$findings, $level, $name, $detail, $path = '') {
        if (count($findings) >= 100) { return; }
        $findings[] = array('level'=>$level,'name'=>$name,'detail'=>$detail,'path'=>$path);
    }
    private static function safe_relative($path) {
        $root = wp_normalize_path(ABSPATH);
        $path = wp_normalize_path($path);
        return strpos($path, $root) === 0 ? substr($path, strlen($root)) : '[ruta fuera de WordPress]';
    }
    // Los campos solo admiten rutas locales absolutas a logs legibles.
    private static function validate_log_path($value) {
        $value = trim((string) $value);
        if ($value === '') { return array('', ''); }
        if (strlen($value) > 1024 || strpos($value, "\0") !== false || preg_match('/[\x00-\x1f\x7f]/', $value)) {
            return array('', 'La ruta contiene caracteres no permitidos o es demasiado larga.');
        }
        // Evita wrappers como php://, http:// y rutas relativas.
        if ($value[0] !== '/' || strpos($value, '://') !== false) {
            return array('', 'Introduce una ruta absoluta local que comience por /.');
        }
        if (!preg_match('/(?:\.log(?:\.[0-9]+)?|\.txt|access_log|error_log|messages)$/i', $value)) {
            return array('', 'Solo se permiten archivos de registro con nombres habituales (.log, .txt, access_log, error_log).');
        }
        if (is_link($value)) { return array('', 'No se permiten enlaces simbolicos.'); }
        $real = realpath($value);
        if ($real === false || !is_file($real) || !is_readable($real)) {
            return array('', 'El archivo no existe o PHP no tiene permisos de lectura.');
        }
        if (is_link($real)) { return array('', 'No se permiten enlaces simbolicos.'); }
        return array($real, '');
    }
    private static function log_paths() {
        $saved = get_option(self::LOGS_OPTION, array());
        $paths = array();
        if (is_array($saved)) {
            foreach (array('http', 'php') as $key) {
                if (!empty($saved[$key]) && is_string($saved[$key])) { $paths[] = $saved[$key]; }
            }
        }
        // Compatibilidad con la configuracion previa, si no hay rutas guardadas.
        if (!$paths && defined('AWP_PHP2SHELL_LOG_PATHS') && is_array(AWP_PHP2SHELL_LOG_PATHS)) {
            foreach (array_slice(AWP_PHP2SHELL_LOG_PATHS, 0, 2) as $p) {
                if (is_string($p)) { $paths[] = $p; }
            }
        }
        return array_values(array_unique($paths));
    }
    public static function save_logs() {
        if (!current_user_can('manage_options')) { wp_die('Acceso denegado.', '', array('response'=>403)); }
        check_admin_referer(self::SETTINGS_NONCE);
        $input = isset($_POST['awp_logs']) && is_array($_POST['awp_logs']) ? wp_unslash($_POST['awp_logs']) : array();
        $paths = array(); $errors = array();
        foreach (array('http'=>'HTTP / servidor web', 'php'=>'PHP-FPM / errores PHP') as $key=>$label) {
            $raw = isset($input[$key]) && is_string($input[$key]) ? $input[$key] : '';
            list($valid, $error) = self::validate_log_path($raw);
            $paths[$key] = $valid;
            if ($error) { $errors[] = $label.': '.$error; }
        }
        if ($errors) {
            set_transient('awp_php2shell_settings_error_'.get_current_user_id(), implode(' ', $errors), MINUTE_IN_SECONDS);
            // No guardar parcialmente ni reflejar rutas invalidas en la URL.
        } else {
            update_option(self::LOGS_OPTION, $paths, false);
        }
        wp_safe_redirect(admin_url('tools.php?page='.self::SLUG.'&settings='.($errors?'error':'saved')));
        exit;
    }
    private static function inspect_logs(&$findings, &$stats, $start) {
        $paths = self::log_paths();
        $stats['logs_configured'] = count($paths);
        $stats['logs_read'] = 0;
        $stats['log_lines'] = 0;
        foreach ($paths as $path) {
            if (microtime(true) - $start > self::MAX_SECONDS) { $stats['logs_limited'] = true; break; }
            if (!is_file($path) || is_link($path) || !is_readable($path)) {
                self::add($findings, 'info', 'Log no disponible', 'La ruta configurada no es un archivo legible o es un enlace simbolico.', '[log configurado]');
                continue;
            }
            $size = @filesize($path);
            if ($size === false) { continue; }
            $handle = @fopen($path, 'rb');
            if (!$handle) { continue; }
            $stats['logs_read']++;
            if ($size > self::MAX_LOG_BYTES) { @fseek($handle, -self::MAX_LOG_BYTES, SEEK_END); @fgets($handle); $stats['logs_limited'] = true; }
            $count = 0;
            $matches = array('upload_progress'=>0, 'oom'=>0, 'crash'=>0, 'suspicious'=>0);
            while (!feof($handle) && $count < self::MAX_LOG_LINES && microtime(true) - $start < self::MAX_SECONDS) {
                $line = fgets($handle, 16384);
                if ($line === false) { break; }
                $count++;
                if (stripos($line, 'PHP_SESSION_UPLOAD_PROGRESS') !== false) { $matches['upload_progress']++; }
                if (preg_match('/out of memory|allowed memory size.*exhausted|zend_mm_heap corrupted/i', $line)) { $matches['oom']++; }
                if (preg_match('/segmentation fault|segfault|core dumped/i', $line)) { $matches['crash']++; }
                if (preg_match('/(?:\/bin\/(?:sh|bash)|\bcurl\s+https?:\/\/|\bwget\s+https?:\/\/)/i', $line)) { $matches['suspicious']++; }
            }
            fclose($handle);
            $stats['log_lines'] += $count;
            if ($count >= self::MAX_LOG_LINES) { $stats['logs_limited'] = true; }
            // No almacenar lineas completas: pueden contener cookies, tokens y datos personales.
            $summary = array();
            foreach ($matches as $key=>$value) { if ($value) { $summary[] = $key.': '.$value; } }
            if ($summary) {
                self::add($findings, 'medium', 'Patrones a investigar en logs', implode('; ', $summary).'. Son coincidencias heuristicas, no prueban explotacion.', '[log '.(int)$stats['logs_read'].']');
            }
        }
    }
    private static function inspect_cron(&$findings, &$stats) {
        $cron = _get_cron_array();
        $stats['wpcron_events'] = 0;
        $stats['wpcron_suspicious'] = 0;
        if (!is_array($cron)) { return; }
        foreach ($cron as $timestamp=>$hooks) {
            foreach ($hooks as $hook=>$instances) {
                $stats['wpcron_events'] += count($instances);
                if (preg_match('/(?:base64_decode|eval\s*\(|shell_exec|passthru|rank1cdn)/i', (string)$hook)) {
                    $stats['wpcron_suspicious']++;
                    self::add($findings, 'medium', 'Hook WP-Cron sospechoso', 'Nombre de evento atipico: '.$hook.'. Comprobar origen y callback.');
                }
            }
        }
    }
    private static function inspect_system_cron(&$findings, &$stats) {
        $stats['system_cron_checked'] = 0;
        $stats['system_cron_matches'] = 0;
        // Solo cron global accesible en lectura; no invocar comandos ni recorrer /etc indiscriminadamente.
        foreach (array('/etc/crontab','/etc/cron.d') as $location) {
            $files = array();
            if (is_file($location)) { $files[] = $location; }
            elseif (is_dir($location) && is_readable($location)) {
                $names = @scandir($location);
                if (is_array($names)) {
                    foreach (array_slice($names, 0, 30) as $name) {
                        if ($name !== '.' && $name !== '..') { $files[] = $location.'/'.$name; }
                    }
                }
            }
            foreach ($files as $file) {
                if (!is_file($file) || is_link($file) || !is_readable($file) || @filesize($file) > 131072) { continue; }
                $content = @file_get_contents($file, false, null, 0, 131072);
                if ($content === false) { continue; }
                $stats['system_cron_checked']++;
                if (preg_match('/(?:base64_decode|curl\s+https?:\/\/|wget\s+https?:\/\/|\/tmp\/.*\.php)/i', $content)) {
                    $stats['system_cron_matches']++;
                    self::add($findings, 'medium', 'Patron en cron del sistema', 'Se detecto un comando que merece revision. Puede ser legitimo.', '[cron del sistema]');
                }
            }
        }
    }
    private static function scan() {
        $start = microtime(true);
        $findings = array();
        $checked = 0;
        $limited = false;
        $status = self::status();
        $stats = array('logs_limited'=>false);
        self::inspect_logs($findings, $stats, $start);
        self::inspect_cron($findings, $stats);
        self::inspect_system_cron($findings, $stats);
        $users = get_users(array('role'=>'administrator', 'fields'=>array('ID','user_login','user_email','user_registered'), 'number'=>500));
        foreach ($users as $user) {
            if (preg_match('/^wpsupport_/i', $user->user_login) || preg_match('/@wp-mail\.net$/i', $user->user_email)) {
                self::add($findings, 'high', 'Cuenta administradora con indicador conocido', 'Compruebe la legitimidad del usuario ID '.$user->ID.' ('.$user->user_login.').');
            }
        }
        $suspicious_options = array('_uf6qdn2hmm','t8krdk990phb','_np5pvf754c');
        global $wpdb;
        foreach ($suspicious_options as $opt) {
            $exists = $wpdb->get_var($wpdb->prepare("SELECT option_name FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $opt));
            if ($exists !== null) {
                self::add($findings, 'high', 'Opcion de base de datos sospechosa', 'Se detecto la opcion '.$opt.'; es un indicador de otro incidente conocido, no una prueba especifica de PHP2Shell.');
            }
        }
        $unexpected = ABSPATH.'wp-includes/class-wp-cache-util.php';
        if (is_file($unexpected)) {
            self::add($findings, 'high', 'Archivo no habitual del nucleo', 'Archivo conocido en investigaciones de malware; verificar manualmente.', self::safe_relative($unexpected));
        }
        $roots = array(WP_CONTENT_DIR.'/uploads', WP_CONTENT_DIR.'/mu-plugins', WP_CONTENT_DIR.'/plugins', WP_CONTENT_DIR.'/themes');
        $excluded = array('.git','node_modules','vendor','cache','upgrade','backups','ai1wm-backups');
        $cutoff = time() - 7 * DAY_IN_SECONDS;
        foreach ($roots as $root) {
            if (!is_dir($root) || is_link($root)) { continue; }
            try {
                $directory = new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS);
                $filter = new RecursiveCallbackFilterIterator($directory, function($current) use ($excluded) {
                    if ($current->isLink()) { return false; }
                    if ($current->isDir() && in_array($current->getFilename(), $excluded, true)) { return false; }
                    return true;
                });
                $it = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::LEAVES_ONLY);
                foreach ($it as $file) {
                    if (++$checked > self::MAX_FILES || microtime(true) - $start > self::MAX_SECONDS) { $limited = true; break 2; }
                    if (!$file->isFile() || $file->isLink()) { continue; }
                    $path = $file->getPathname();
                    $relative = self::safe_relative($path);
                    // Evitar que las firmas del propio auditor generen falsos positivos.
                    if (wp_normalize_path($path) === wp_normalize_path(__FILE__)) { continue; }
                    $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                    if (!in_array($extension, array('php','phtml','phar','htaccess'), true) && basename($path) !== '.htaccess') { continue; }
                    $is_upload = strpos(wp_normalize_path($path), wp_normalize_path(WP_CONTENT_DIR.'/uploads/')) === 0;
                    if ($is_upload && in_array($extension, array('php','phtml','phar'), true)) {
                        // Los index.php vacios o de proteccion de directorios son comunes en plugins legitimos.
                        $is_guard = false;
                        if (strtolower(basename($path)) === 'index.php' && $file->getSize() <= 2048) {
                            $guard = @file_get_contents($path, false, null, 0, 2048);
                            if (is_string($guard)) {
                                $normalized = preg_replace('~/\*.*?\*/|//[^\r\n]*|\#[^\r\n]*~s', '', $guard);
                                $normalized = preg_replace('/\s+/', '', $normalized);
                                $is_guard = (bool) preg_match('/^<\?php(?:exit\(?\)?;?|die\(?\)?;?|return;?)?(?:\?>)?$/i', $normalized);
                            }
                        }
                        if (!$is_guard) {
                            self::add($findings, 'medium', 'PHP en uploads requiere revision', 'La ubicacion no demuestra infeccion. Comprobar contenido y origen.', $relative);
                        }
                    }
                    if ($file->getMTime() >= $cutoff && in_array($extension, array('php','phtml','phar'), true)) {
                        self::add($findings, 'info', 'Archivo PHP modificado recientemente', 'Modificado durante los ultimos 7 dias; puede ser una actualizacion legitima.', $relative);
                    }
                    if ($file->getSize() > self::MAX_FILE_SIZE || $file->getSize() === 0) { continue; }
                    $data = @file_get_contents($path, false, null, 0, self::MAX_FILE_SIZE);
                    if ($data === false) { continue; }
                    if (stripos($data, 'rank1cdn.com') !== false || strpos($data, '#ms6v46') !== false) {
                        self::add($findings, 'high', 'Indicador textual de malware conocido', 'Coincidencia con indicador de otro incidente; revisar manualmente.', $relative);
                    }
                    if (preg_match('/\beval\s*\(\s*base64_decode\s*\(/i', $data) || preg_match('/\b(?:assert|eval)\s*\(\s*gzinflate\s*\(/i', $data)) {
                        self::add($findings, 'medium', 'Patron de PHP potencialmente ofuscado', 'Patron heuristico: tambien puede aparecer en software legitimo.', $relative);
                    }
                }
            } catch (Exception $e) {
                self::add($findings, 'info', 'Directorio inaccesible', 'No se pudo examinar completamente una carpeta.', self::safe_relative($root));
            }
        }
        return array('date'=>current_time('mysql'), 'php'=>$status, 'findings'=>$findings, 'files'=>$checked, 'limited'=>$limited, 'stats'=>$stats,
            'notice'=>'Analiza logs HTTP/PHP-FPM solo si se configuran rutas legibles, WP-Cron y cron global accesible. NO inspecciona memoria, procesos ni trafico de red. Los indicadores no prueban explotacion de PHP2Shell.');
    }
    public static function run() {
        if (!current_user_can('manage_options')) { wp_die('Acceso denegado.', '', array('response'=>403)); }
        check_admin_referer(self::NONCE);
        $report = self::scan();
        set_transient(self::TRANSIENT_PREFIX.get_current_user_id(), $report, HOUR_IN_SECONDS);
        wp_safe_redirect(admin_url('tools.php?page='.self::SLUG.'&scanned=1'));
        exit;
    }
    public static function page() {
        if (!current_user_can('manage_options')) { return; }
        $php = self::status();
        $report = get_transient(self::TRANSIENT_PREFIX.get_current_user_id());
        $labels = array('corrected'=>'Version corregida segun numeracion oficial','potential'=>'Version potencialmente vulnerable','unsupported'=>'Rama antigua: verificar soporte','unknown'=>'Estado no determinado');
        echo '<style>
        .awp-findings{max-width:1100px;border-collapse:separate;border-spacing:0 7px;background:transparent!important;border:0!important}
        .awp-findings thead th{background:#142c4d;color:#fff;padding:13px 14px;border:0}
        .awp-findings tbody tr td{padding:13px 14px;background:#fff;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0;vertical-align:middle}
        .awp-findings tbody tr td:first-child{border-left:5px solid #94a3b8;border-radius:7px 0 0 7px}
        .awp-findings tbody tr td:last-child{border-right:1px solid #e2e8f0;border-radius:0 7px 7px 0}
        .awp-findings .awp-level-high td{background:#fff1f2;border-color:#fecdd3}
        .awp-findings .awp-level-high td:first-child{border-left-color:#dc2626}
        .awp-findings .awp-level-medium td{background:#fff7ed;border-color:#fed7aa}
        .awp-findings .awp-level-medium td:first-child{border-left-color:#ea580c}
        .awp-findings .awp-level-info td{background:#eff6ff;border-color:#bfdbfe}
        .awp-findings .awp-level-info td:first-child{border-left-color:#2563eb}
        .awp-pill{display:inline-block;padding:5px 11px;border-radius:99px;font-weight:700;font-size:12px;white-space:nowrap}
        .awp-pill-high{color:#991b1b;background:#fecaca}
        .awp-pill-medium{color:#9a3412;background:#fed7aa}
        .awp-pill-info{color:#1e40af;background:#bfdbfe}
        .awp-php-status{max-width:1000px;background:#fff;padding:18px 22px;border-left:5px solid #64748b;margin:16px 0;border-radius:7px}
        .awp-php-corrected{border-left-color:#16a34a;background:#f0fdf4}
        .awp-php-potential{border-left-color:#dc2626;background:#fff1f2}
        .awp-php-unsupported{border-left-color:#ea580c;background:#fff7ed}
        @media(max-width:782px){.awp-findings{display:block;overflow-x:auto;white-space:normal}.awp-findings th,.awp-findings td{min-width:115px}}

        /* Modo oscuro: limitado exclusivamente al contenido del auditor */
        .awp-audit{--awp-bg:#ffffff;--awp-text:#1f2937;--awp-muted:#475569;--awp-line:#dbe4f0;--awp-code:#f1f5f9;--awp-panel:#ffffff;--awp-tablehead:#142c4d;color:var(--awp-text);padding:12px 18px 25px;border-radius:12px;transition:background .15s,color .15s}
        .awp-audit .awp-logs-form{padding:16px;border:1px solid var(--awp-line);border-radius:10px;max-width:740px;background:var(--awp-panel)}
        .awp-audit .awp-logs-form input.regular-text{width:100%;max-width:680px;box-sizing:border-box}
        .awp-audit.awp-dark .awp-logs-form input.regular-text{background:#0e1b2d;color:#e5edf8;border-color:#44617f}
        .awp-audit-brand{display:flex;align-items:center;gap:14px;min-width:0}
        .awp-audit-brand img{width:64px;height:64px;object-fit:contain;flex-shrink:0;filter:drop-shadow(0 3px 6px rgba(15,42,78,.18))}
        .awp-audit-brand h1{margin:0!important;line-height:1.3}
        @media(max-width:600px){.awp-audit-brand img{width:48px;height:48px}.awp-audit-brand h1{font-size:21px}}
        .awp-audit-top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
        .awp-audit h1,.awp-audit h2,.awp-audit p,.awp-audit strong{color:inherit}
        .awp-audit pre{padding:14px;max-width:100%;overflow-x:auto;border-radius:8px;background:var(--awp-code);color:var(--awp-text)}
        .awp-audit code{background:var(--awp-code);color:var(--awp-text);padding:2px 5px;border-radius:4px;overflow-wrap:anywhere}
        .awp-audit .awp-findings thead th{background:var(--awp-tablehead)!important;color:#fff!important}
        .awp-audit .awp-php-status{color:#1f2937}
        .awp-audit.awp-dark{color:#e5edf8;background:#0d1626;--awp-text:#e5edf8;--awp-muted:#b9c8dc;--awp-line:#334155;--awp-code:#1e293b;--awp-panel:#142338;--awp-tablehead:#1e3a5f}
        .awp-audit.awp-dark .awp-php-status{background:#142338;color:#e5edf8;border-left-color:#64748b}
        .awp-audit.awp-dark .awp-php-corrected{background:#0e332b;border-left-color:#34d399}
        .awp-audit.awp-dark .awp-php-potential{background:#3b1d2a;border-left-color:#fb7185}
        .awp-audit.awp-dark .awp-php-unsupported{background:#3d2b1d;border-left-color:#fb923c}
        .awp-audit.awp-dark .awp-findings tbody tr td{background:#142338;color:#e5edf8;border-top-color:#334155;border-bottom-color:#334155}
        .awp-audit.awp-dark .awp-findings tbody tr td:last-child{border-right-color:#334155}
        .awp-audit.awp-dark .awp-findings .awp-level-high td{background:#3b1d2a;border-color:#793348}
        .awp-audit.awp-dark .awp-findings .awp-level-medium td{background:#3d2b1d;border-color:#76512c}
        .awp-audit.awp-dark .awp-findings .awp-level-info td{background:#172d4b;border-color:#2a4d7b}
        .awp-audit.awp-dark .awp-pill-high{background:#7f1d1d;color:#ffe4e6}
        .awp-audit.awp-dark .awp-pill-medium{background:#7c3e11;color:#ffedd5}
        .awp-audit.awp-dark .awp-pill-info{background:#1e40af;color:#dbeafe}
        .awp-audit.awp-dark .notice{background:#192b42;color:#e5edf8;border-top:1px solid #334155;border-right:1px solid #334155;border-bottom:1px solid #334155}
        .awp-audit.awp-dark .notice p{color:#e5edf8}
        .awp-audit.awp-dark .notice-info{border-left-color:#60a5fa}
        .awp-audit.awp-dark .notice-warning{border-left-color:#fbbf24}
        .awp-audit.awp-dark .notice-success{border-left-color:#34d399}
        .awp-audit.awp-dark #awp-theme-toggle{background:#203550;border-color:#44617f;color:#fff}
        .awp-audit.awp-dark .button-primary{background:#2563eb;border-color:#3b82f6;color:#fff}
        .awp-audit.awp-dark a{color:#93c5fd}
        @media(max-width:782px){.awp-audit{padding:10px}.awp-audit-top h1{font-size:21px}}
        </style>';
        echo '<div class="wrap awp-audit" id="awp-php2shell-ui"><div class="awp-audit-top"><div class="awp-audit-brand"><img src="'.esc_url(plugin_dir_url(__FILE__).'assets/analisiswp-buho.webp').'" alt="Búho de AnalisisWP" width="64" height="64" /><h1>AnalisisWP · Auditor PHP2Shell</h1></div><button type="button" id="awp-theme-toggle" class="button" aria-pressed="false">🌙 Modo oscuro</button></div>';
        echo '<p>Diagnostico local de solo lectura. No modifica archivos, usuarios ni configuraciones.</p>';
        echo '<div class="awp-php-status awp-php-'.esc_attr($php['state']).'">';
        echo '<h2 style="margin-top:0">Version PHP: '.self::esc($php['version']).'</h2>';
        echo '<p><strong>Estado:</strong> '.self::esc($labels[$php['state']]).'</p>';
        echo '<p><strong>Version minima corregida en esta rama:</strong> '.self::esc($php['fixed']).'</p>';
        echo '<p>'.self::esc($php['note']).'</p></div>';
        echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';
        echo '<input type="hidden" name="action" value="awp_php2shell_scan">';
        wp_nonce_field(self::NONCE);
        submit_button('Ejecutar auditoria de indicadores', 'primary', 'submit', false);
        echo '</form>';
        if (is_array($report)) {
            echo '<h2>Ultimo analisis: '.self::esc($report['date']).'</h2>';
            $st = isset($report['stats']) ? $report['stats'] : array();
            echo '<p><strong>Logs:</strong> '.(int)($st['logs_read'] ?? 0).' de '.(int)($st['logs_configured'] ?? 0).' leidos; '.(int)($st['log_lines'] ?? 0).' lineas examinadas. <strong>WP-Cron:</strong> '.(int)($st['wpcron_events'] ?? 0).' eventos. <strong>Cron del sistema:</strong> '.(int)($st['system_cron_checked'] ?? 0).' archivos accesibles.</p>';
            if (!empty($st['logs_limited'])) { echo '<div class="notice notice-warning inline"><p>Revision de logs parcial por limites de tamano, tiempo o lineas.</p></div>'; }
            if (empty($st['logs_configured'])) { echo '<div class="notice notice-info inline"><p>No se han configurado rutas de logs. El analisis de HTTP/PHP-FPM no se ha realizado.</p></div>'; }
            echo '<p>Archivos recorridos: '.(int)$report['files'].'. Hallazgos: '.count($report['findings']).'.</p>';
            if ($report['limited']) { echo '<div class="notice notice-warning inline"><p>Analisis parcial: se alcanzo el limite de tiempo o archivos.</p></div>'; }
            echo '<div class="notice notice-info inline"><p>'.self::esc($report['notice']).'</p></div>';
            if (!$report['findings']) { echo '<div class="notice notice-success inline"><p>No se detectaron indicadores en las comprobaciones realizadas. Esto NO descarta una intrusión.</p></div>'; }
            else {
                echo '<table class="widefat awp-findings"><thead><tr><th>Nivel</th><th>Hallazgo</th><th>Detalle</th><th>Ruta relativa</th></tr></thead><tbody>';
                foreach ($report['findings'] as $f) {
                    $level = in_array($f['level'], array('high','medium','info'), true) ? $f['level'] : 'info';
                    $level_labels = array('high'=>'ALTO', 'medium'=>'MEDIO', 'info'=>'INFORMATIVO');
                    echo '<tr class="awp-level-'.esc_attr($level).'"><td><span class="awp-pill awp-pill-'.esc_attr($level).'">'.self::esc($level_labels[$level]).'</span></td><td><strong>'.self::esc($f['name']).'</strong></td><td>'.self::esc($f['detail']).'</td><td><code>'.self::esc($f['path']).'</code></td></tr>';
                }
                echo '</tbody></table>';
            }
        }
        echo '<h2>Rutas de los registros del servidor</h2>';
        echo '<p>Configura las rutas absolutas de tus dos logs directamente desde el panel. Solo administradores pueden guardarlas. Se validan antes de almacenar y no se muestra su contenido.</p>';
        if (isset($_GET['settings']) && $_GET['settings'] === 'saved') { echo '<div class="notice notice-success inline"><p>Rutas guardadas correctamente.</p></div>'; }
        if (isset($_GET['settings']) && $_GET['settings'] === 'error') {
            $err = get_transient('awp_php2shell_settings_error_'.get_current_user_id());
            if ($err) { echo '<div class="notice notice-error inline"><p>'.self::esc($err).'</p></div>'; delete_transient('awp_php2shell_settings_error_'.get_current_user_id()); }
        }
        $saved_paths = get_option(self::LOGS_OPTION, array());
        if (!is_array($saved_paths)) { $saved_paths = array(); }
        echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" class="awp-logs-form">';
        echo '<input type="hidden" name="action" value="awp_php2shell_save_logs">';
        wp_nonce_field(self::SETTINGS_NONCE);
        echo '<p><label for="awp-log-http"><strong>Log HTTP (Apache / Nginx / LiteSpeed)</strong></label></p>';
        echo '<input type="text" class="regular-text" id="awp-log-http" name="awp_logs[http]" autocomplete="off" spellcheck="false" placeholder="/var/log/apache2/access.log" value="'.esc_attr(isset($saved_paths['http'])?$saved_paths['http']:'').'">';
        echo '<p><label for="awp-log-php"><strong>Log PHP-FPM / errores PHP</strong></label></p>';
        echo '<input type="text" class="regular-text" id="awp-log-php" name="awp_logs[php]" autocomplete="off" spellcheck="false" placeholder="/var/log/php-fpm/error.log" value="'.esc_attr(isset($saved_paths['php'])?$saved_paths['php']:'').'">';
        echo '<p class="description">Puedes dejar un campo vacio. Las rutas deben existir y ser legibles por PHP. El acceso puede estar restringido en hosting compartido.</p>';
        submit_button('Guardar rutas de logs', 'secondary', 'submit', false);
        echo '</form>';
        echo '<p>El analisis revisa como maximo 2 MB y 3500 lineas por log, sin modificar los archivos. Las rutas configuradas previamente en wp-config.php se mantienen como alternativa si no hay rutas guardadas.</p>';
        echo '<h2>Que no puede confirmar este plugin</h2><p>Un plugin WordPress no puede demostrar por si solo si PHP2Shell se exploto. Para una investigacion fiable hacen falta logs del servidor, registros de PHP-FPM, integridad de archivos y, si procede, analisis forense.</p>';

        echo '<script>(function(){
          var root=document.getElementById("awp-php2shell-ui"),button=document.getElementById("awp-theme-toggle");
          if(!root||!button)return;
          var key="awp_php2shell_dark";
          function setTheme(dark){root.classList.toggle("awp-dark",dark);button.textContent=dark?"☀️ Modo claro":"🌙 Modo oscuro";button.setAttribute("aria-pressed",dark?"true":"false");}
          var saved="";try{saved=localStorage.getItem(key)||"";}catch(e){}
          setTheme(saved==="1");
          button.addEventListener("click",function(){var dark=!root.classList.contains("awp-dark");setTheme(dark);try{localStorage.setItem(key,dark?"1":"0");}catch(e){}});
        })();</script>';
        echo '<p><strong>Consejo:</strong> si el hosting aplica backports de seguridad, consulta su aviso antes de interpretar la numeracion PHP como vulnerable.</p></div>';
    }
}
AWP_PHP2Shell_Auditor::init();
