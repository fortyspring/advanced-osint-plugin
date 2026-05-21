<?php
/**
 * Plugin Name:       Advanced OSINT Processing Plugin
 * Plugin URI:        https://beiruttime.com
 * Description:       إضافة ووردبريس متقدمة لمعالجة استخبارات المصادر المفتوحة (OSINT) v9.0-Production — تصنيف هجين شجري تلقائي، جلب إحداثيات جغرافية، وصندوق تحرير مدمج.
 * Version:           9.0.0
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * Author:            BeirutTime / MQ-OSINT
 * Author URI:        https://beiruttime.com
 * Text Domain:       advanced-osint
 * License:           GPL-2.0-or-later
 * @package           Advanced_OSINT
 */
if(!defined('ABSPATH')){exit;}
define('AOSINT_VERSION','9.0.0');
define('AOSINT_FILE',__FILE__);
define('AOSINT_DIR',plugin_dir_path(__FILE__));
define('AOSINT_URL',plugin_dir_url(__FILE__));
if(!defined('AOSINT_GEO_API')){define('AOSINT_GEO_API','https://api.beiruttime-nlp.local/v1/geo/extract');}
define('AOSINT_TIMEOUT',5);
if(!function_exists('mb_stripos')){function mb_stripos(string $h,string $n,int $o=0,string $e=''){return stripos($h,$n,$o);}}
if(!function_exists('mb_strlen')){function mb_strlen(string $s,string $e=''):int{return(int)preg_match_all('/./us',$s);}}
if(!function_exists('mb_substr')){function mb_substr(string $s,int $st,?int $l=null,string $e=''):string{$c=preg_split('//u',$s,-1,PREG_SPLIT_NO_EMPTY)?:[];return implode('',$l===null?array_slice($c,$st):array_slice($c,$st,$l));}}
if(!function_exists('mb_strpos')){function mb_strpos(string $h,string $n,int $o=0,string $e=''){return strpos($h,$n,$o);}}

/**
 * AOSINT_Taxonomy
 * القاموس الشجري الكامل لـ OSINT v9.0 مع محرك التصنيف الهجين.
 * classify() يعيد: primary_category, secondary_categories, confidence_score, matched_terms
 */
final class AOSINT_Taxonomy{
    private static array $dictionary=[
        'سياسي'=>['العملية_السياسية'=>['انتخابات','برلمان','دستور'],'الدبلوماسية_والعلاقات'=>['سفارة','سفير','مفاوضات','الوسيط الباكستاني']],
        'أمني'=>['الاستخبارات_والمعلومات'=>['استخبارات','جهاز أمني','اختراق أمني'],'إنفاذ_القانون'=>['مداهمة','طوق أمني']],
        'عسكري'=>['القوات_والتشكيلات'=>['قوات برية','اللواء 401','كتيبة هندسية'],'العتاد_والتسليح'=>['دبابة ميركافا','جرافة D9','مسيرات انقضاضية']],
        'اقتصادي'=>['المؤشرات_الكلية'=>['تضخم','عجز مالي'],'التجارة_والموارد'=>['إمدادات الطاقة','محطات الوقود']],
        'نفسي'=>['العمليات_الإدراكية'=>['حرب نفسية','كي الوعي','بروباغندا'],'التأثير_الجمعي'=>['ذعر عام','انهيار معنويات']],
        'إعلامي'=>['الوسائط_والتغطية'=>['مراسل الميادين','وكالة تاس','نشرة عاجلة']],
        'تهديدات'=>['الإنذار_والمؤشرات'=>['على أهبة الاستعداد','الخطوط الحمراء'],'طبيعة_التهديد'=>['تهديد وجودي','بنك أهداف']],
        'دفاع'=>['المنظومات_الاعتراضية'=>['قبة حديدية','صواريخ اعتراضية'],'التحصين'=>['صفارات إنذار','ملاجئ']],
        'هجوم'=>['الهجمات_الجوية'=>['غارة جوية','صلية صاروخية'],'الهجمات_البرية'=>['نسف مباني','اشتباك من مسافة صفر']],
        'حصار'=>['أنواع_الحصار'=>['إغلاق معابر','مضيق هرمز'],'التداعيات'=>['قطع إمدادات','أزمة وقود']],
        'كوارث'=>['الطبيعية'=>['حرائق غابات','زلزال'],'الاصطناعية'=>['تسرب كيميائي','انهيار سدود']],
        'سايبر'=>['طرق_الهجوم'=>['هجوم سيبراني','مجموعة حنظلة','DDoS']],
    ];
    public static function get_dictionary():array{return self::$dictionary;}
    public static function classify(string $title,string $content):array{
        $text=self::normalize($title.' '.wp_strip_all_tags($content));
        $scores=$matched=[];
        foreach(self::$dictionary as $primary=>$sub_groups){
            $scores[$primary]=0;$matched[$primary]=[];
            foreach($sub_groups as $terms){foreach($terms as $term){if(mb_stripos($text,self::normalize($term))!==false){$scores[$primary]++;$matched[$primary][]=$term;}}}
        }
        arsort($scores);$cats=array_keys($scores);$primary_cat=$cats[0]??'غير محدد';$primary_score=$scores[$primary_cat]??0;
        $secondary=[];foreach($scores as $cat=>$score){if($cat!==$primary_cat&&$score>0){$secondary[]=$cat;}}
        $total=0;foreach(self::$dictionary as $sg){foreach($sg as $t){$total+=count($t);}}
        $raw=$total>0?(array_sum($scores)/$total)*100:0;
        if($primary_score>0&&$raw<40){$raw=40+($primary_score*5);}
        $conf=(int)min(99,max(0,round($raw)));
        return['primary_category'=>$primary_score>0?$primary_cat:'غير محدد','secondary_categories'=>$secondary,'confidence_score'=>$conf,'matched_terms'=>$matched];
    }
    public static function normalize(string $text):string{
        $text=(string)preg_replace('/[\x{064B}-\x{065F}\x{0670}]/u','',$text);
        $text=(string)preg_replace('/[إأآ]/u','ا',$text);
        $text=(string)preg_replace('/ة/u','ه',$text);
        return $text;
    }
}

/**
 * AOSINT_Geo_Service
 * detect_location() — كشف اسم مكان من النص عبر مؤشرات لغوية
 * fetch()           — POST إلى AOSINT_GEO_API (timeout=5s) → إحداثيات
 */
final class AOSINT_Geo_Service{
    public static function detect_location(string $text):string{
        $indicators=['في ','إلى ','بمنطقة ','بمحافظة ','بمدينة ','بحي ','قرب ','شمال ','جنوب ','شرق ','غرب ','وسط ','بلدة ','قرية ','مخيم ','ميناء ','مطار '];
        $clean=wp_strip_all_tags($text);
        foreach($indicators as $ind){
            $pos=mb_strpos($clean,$ind);if($pos===false){continue;}
            $after=mb_substr($clean,$pos+mb_strlen($ind),40);
            $parts=preg_split('/[\s\n،,؛;.\-]/u',trim($after),3)?:[];
            $name=isset($parts[0])?trim($parts[0]):'';
            if(mb_strlen($name)>2){return $name;}
        }
        return'';
    }
    public static function fetch(string $title,string $content,string $location_raw):array{
        $payload=(string)wp_json_encode(['title'=>sanitize_text_field($title),'content'=>wp_strip_all_tags($content),'location_raw'=>sanitize_text_field($location_raw)]);
        $response=wp_remote_post(AOSINT_GEO_API,['timeout'=>AOSINT_TIMEOUT,'redirection'=>0,'headers'=>['Content-Type'=>'application/json; charset=utf-8','Accept'=>'application/json','X-Source'=>'aosint-wp/'.AOSINT_VERSION],'body'=>$payload,'data_format'=>'body','blocking'=>true]);
        if(is_wp_error($response)){error_log('[AOSINT Geo] فشل: '.$response->get_error_message());return['success'=>false,'latitude'=>null,'longitude'=>null,'geo_precision'=>'','error'=>$response->get_error_message()];}
        $code=(int)wp_remote_retrieve_response_code($response);$body=(string)wp_remote_retrieve_body($response);
        if($code!==200){error_log(sprintf('[AOSINT Geo] HTTP %d — %s',$code,substr($body,0,500)));return['success'=>false,'latitude'=>null,'longitude'=>null,'geo_precision'=>'','error'=>'HTTP '.$code];}
        $data=json_decode($body,true);
        if(!is_array($data)){error_log('[AOSINT Geo] JSON غير صالح: '.substr($body,0,500));return['success'=>false,'latitude'=>null,'longitude'=>null,'geo_precision'=>'','error'=>'JSON غير صالح'];}
        return['success'=>true,'latitude'=>isset($data['latitude'])?(float)$data['latitude']:null,'longitude'=>isset($data['longitude'])?(float)$data['longitude']:null,'geo_precision'=>isset($data['geo_precision'])?sanitize_text_field((string)$data['geo_precision']):''];
    }
}

/**
 * AOSINT_Meta_Box
 * يُسجّل Meta Box في محرر المقال (Gutenberg + Classic).
 * يعرض التصنيفات والإحداثيات مع شريط دقة ملوّن وخريطة OpenStreetMap.
 * يحفظ التعديلات اليدوية: nonce → صلاحيات → sanitize → update_post_meta
 */
final class AOSINT_Meta_Box{
    public static function init():void{add_action('add_meta_boxes',[self::class,'register']);add_action('save_post',[self::class,'save'],20,2);add_action('admin_enqueue_scripts',[self::class,'enqueue_assets']);}
    public static function register():void{add_meta_box('aosint_meta_box','🧠 OSINT — التصنيف الذكي والإحداثيات الجغرافية',[self::class,'render'],'post','normal','high');}
    public static function enqueue_assets(string $hook):void{if(!in_array($hook,['post.php','post-new.php'],true)){return;}wp_add_inline_style('wp-admin',self::inline_css());}
    public static function render(\WP_Post $post):void{
        wp_nonce_field('aosint_save_meta_'.$post->ID,'aosint_nonce');
        $pc=(string)get_post_meta($post->ID,'osint_primary_category',true);
        $sc=get_post_meta($post->ID,'osint_secondary_categories',true);
        $cf=(int)get_post_meta($post->ID,'osint_confidence_score',true);
        $lr=(string)get_post_meta($post->ID,'osint_location_raw',true);
        $la=(string)get_post_meta($post->ID,'osint_latitude',true);
        $lo=(string)get_post_meta($post->ID,'osint_longitude',true);
        $gp=(string)get_post_meta($post->ID,'osint_geo_precision',true);
        if(!is_array($sc)){$sc=[];}$bc=self::confidence_color($cf);
        ?>
        <div class="aosint-box" dir="rtl">
        <div class="aosint-panel"><div class="aosint-panel-head"><span>📂</span><h3>التصنيف الهجين (OSINT v9.0)</h3></div>
        <table class="aosint-table">
        <tr><th>التصنيف الرئيسي</th><td><?php if($pc&&$pc!=='غير محدد'):?><span class="aosint-badge aosint-badge-primary"><?php echo esc_html($pc);?></span><?php else:?><em class="aosint-muted">لم يُصنَّف بعد</em><?php endif;?></td></tr>
        <tr><th>التصنيفات الفرعية</th><td><?php if(!empty($sc)):foreach($sc as $cat):?><span class="aosint-badge aosint-badge-secondary"><?php echo esc_html($cat);?></span><?php endforeach;else:?><em class="aosint-muted">لا يوجد</em><?php endif;?></td></tr>
        <tr><th>نسبة الدقة</th><td><div class="aosint-bar-wrap"><div class="aosint-bar-track"><div class="aosint-bar-fill" style="width:<?php echo esc_attr($cf);?>%;background:<?php echo esc_attr($bc);?>;" role="progressbar" aria-valuenow="<?php echo esc_attr($cf);?>" aria-valuemin="0" aria-valuemax="100"></div></div><span class="aosint-bar-label" style="color:<?php echo esc_attr($bc);?>"><?php echo esc_html($cf);?>%</span></div></td></tr>
        </table></div>
        <div class="aosint-panel"><div class="aosint-panel-head"><span>📍</span><h3>البيانات الجغرافية</h3><small class="aosint-note">تعديلك اليدوي يأخذ الأولوية</small></div>
        <table class="aosint-table">
        <tr><th><label for="aosint_location_raw">اسم الموقع</label></th><td><input type="text" id="aosint_location_raw" name="aosint_location_raw" class="aosint-input" value="<?php echo esc_attr($lr);?>" placeholder="مثال: جنوب لبنان"/></td></tr>
        <tr><th><label for="aosint_latitude">خط العرض (Latitude)</label></th><td><input type="text" id="aosint_latitude" name="aosint_latitude" class="aosint-input aosint-coord" value="<?php echo esc_attr($la);?>" placeholder="33.8886" pattern="^-?\d{1,3}(\.\d+)?$"/></td></tr>
        <tr><th><label for="aosint_longitude">خط الطول (Longitude)</label></th><td><input type="text" id="aosint_longitude" name="aosint_longitude" class="aosint-input aosint-coord" value="<?php echo esc_attr($lo);?>" placeholder="35.4955" pattern="^-?\d{1,3}(\.\d+)?$"/></td></tr>
        <tr><th><label for="aosint_geo_precision">دقة الموقع</label></th><td><select id="aosint_geo_precision" name="aosint_geo_precision" class="aosint-input aosint-select"><?php
        foreach([''=> '— غير محدد','حي'=>'حي','بلدة'=>'بلدة','مضيق'=>'مضيق','محافظة'=>'محافظة'] as $v=>$l){printf('<option value="%s"%s>%s</option>',esc_attr($v),selected($gp,$v,false),esc_html($l));}
        ?></select></td></tr>
        </table>
        <?php if($la!==''&&$lo!==''):?><div class="aosint-map-preview"><a href="https://www.openstreetmap.org/?mlat=<?php echo esc_attr($la);?>&mlon=<?php echo esc_attr($lo);?>#map=10/<?php echo esc_attr($la);?>/<?php echo esc_attr($lo);?>" target="_blank" rel="noopener noreferrer" class="aosint-map-link">🗺️ عرض على OpenStreetMap <code>(<?php echo esc_html($la);?>, <?php echo esc_html($lo);?>)</code></a></div><?php endif;?>
        </div>
        <div class="aosint-panel aosint-panel-action"><label class="aosint-reprocess-label"><input type="checkbox" name="aosint_reprocess" value="1"/><strong>إعادة التصنيف والجلب الجغرافي عند الحفظ</strong></label><p class="aosint-hint">✅ يتم التصنيف تلقائياً عند أول نشر.</p></div>
        </div><?php
    }
    public static function save(int $post_id,\WP_Post $post):void{
        if(!isset($_POST['aosint_nonce'])){return;}
        if(!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['aosint_nonce'])),'aosint_save_meta_'.$post_id)){return;}
        if(!current_user_can('edit_post',$post_id)){return;}
        if(defined('DOING_AUTOSAVE')&&DOING_AUTOSAVE){return;}
        if(wp_is_post_revision($post_id)||wp_is_post_autosave($post_id)){return;}
        if(array_key_exists('aosint_location_raw',$_POST)){update_post_meta($post_id,'osint_location_raw',sanitize_text_field(wp_unslash($_POST['aosint_location_raw'])));}
        foreach(['aosint_latitude'=>'osint_latitude','aosint_longitude'=>'osint_longitude'] as $key=>$meta){
            if(array_key_exists($key,$_POST)){$val=sanitize_text_field(wp_unslash($_POST[$key]));if($val===''||preg_match('/^-?\d{1,3}(\.\d+)?$/',$val)){update_post_meta($post_id,$meta,$val);}}
        }
        if(array_key_exists('aosint_geo_precision',$_POST)){$p=sanitize_text_field(wp_unslash($_POST['aosint_geo_precision']));if(in_array($p,['','حي','بلدة','مضيق','محافظة'],true)){update_post_meta($post_id,'osint_geo_precision',$p);}}
    }
    private static function confidence_color(int $s):string{if($s>=80){return'#16a34a';}if($s>=55){return'#d97706';}return'#dc2626';}
    private static function inline_css():string{return'.aosint-box{font-family:"Segoe UI",Tahoma,Arial,sans-serif;direction:rtl;font-size:13px}.aosint-panel{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px 18px;margin-bottom:14px}.aosint-panel-head{display:flex;align-items:center;gap:8px;margin-bottom:12px;border-bottom:2px solid #3b82f6;padding-bottom:8px}.aosint-panel-head h3{margin:0;font-size:14px;font-weight:700;color:#1e3a5f}.aosint-note{color:#64748b;font-size:11px;margin-right:auto}.aosint-table{width:100%;border-collapse:collapse}.aosint-table th{width:165px;padding:7px 10px;text-align:right;color:#374151;font-weight:600;vertical-align:middle}.aosint-table td{padding:7px 10px;vertical-align:middle}.aosint-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600;margin:2px}.aosint-badge-primary{background:#1e40af;color:#fff}.aosint-badge-secondary{background:#dbeafe;color:#1d4ed8}.aosint-muted{color:#9ca3af;font-style:italic}.aosint-bar-wrap{display:flex;align-items:center;gap:10px}.aosint-bar-track{flex:1;max-width:200px;height:14px;background:#e5e7eb;border-radius:7px;overflow:hidden}.aosint-bar-fill{height:100%;border-radius:7px;transition:width .4s ease}.aosint-bar-label{font-size:13px;font-weight:700;min-width:36px}.aosint-input{width:100%;max-width:300px;padding:5px 8px;border:1px solid #d1d5db;border-radius:4px;font-size:13px}.aosint-coord{max-width:160px}.aosint-select{max-width:220px}.aosint-map-preview{margin-top:10px;padding:8px 12px;background:#eff6ff;border-radius:6px;border:1px dashed #93c5fd}.aosint-map-link{color:#2563eb;font-size:12px;text-decoration:none;display:inline-flex;align-items:center;gap:6px}.aosint-map-link:hover{text-decoration:underline}.aosint-map-link code{background:#dbeafe;padding:1px 5px;border-radius:3px;font-size:11px}.aosint-panel-action{background:#fffbeb;border-color:#fde68a}.aosint-reprocess-label{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px}.aosint-hint{margin:8px 0 0;color:#78716c;font-size:12px}';}
}

/**
 * AOSINT_Save_Handler
 * يستمع لـ save_post ويُطلق:
 * أ) AOSINT_Taxonomy::classify() — التصنيف الهجين
 * ب) AOSINT_Geo_Service::fetch() — جلب الإحداثيات من API
 * الشروط: أول نشر أو المحرر طلب إعادة المعالجة
 */
final class AOSINT_Save_Handler{
    public static function init():void{add_action('save_post',[self::class,'handle'],10,3);}
    public static function handle(int $post_id,\WP_Post $post,bool $update):void{
        if(defined('DOING_AUTOSAVE')&&DOING_AUTOSAVE){return;}
        if(wp_is_post_revision($post_id)){return;}if(wp_is_post_autosave($post_id)){return;}
        if($post->post_type!=='post'){return;}if(!current_user_can('edit_post',$post_id)){return;}
        $reprocess=isset($_POST['aosint_reprocess'])&&'1'===sanitize_text_field(wp_unslash($_POST['aosint_reprocess']));
        $not_classified=get_post_meta($post_id,'osint_primary_category',true)==='';
        $is_first_publish=$post->post_status==='publish'&&(!$update||$not_classified);
        if(!$reprocess&&!$is_first_publish){return;}
        $title=(string)$post->post_title;$content=(string)$post->post_content;
        $r=AOSINT_Taxonomy::classify($title,$content);
        update_post_meta($post_id,'osint_primary_category',$r['primary_category']);
        update_post_meta($post_id,'osint_secondary_categories',$r['secondary_categories']);
        update_post_meta($post_id,'osint_confidence_score',$r['confidence_score']);
        $lr=(string)get_post_meta($post_id,'osint_location_raw',true);
        if(empty($lr)){$lr=AOSINT_Geo_Service::detect_location($title.' '.$content);}
        if(!empty($lr)){
            update_post_meta($post_id,'osint_location_raw',sanitize_text_field($lr));
            $geo=AOSINT_Geo_Service::fetch($title,$content,$lr);
            if($geo['success']){
                if($geo['latitude']!==null){update_post_meta($post_id,'osint_latitude',(string)$geo['latitude']);}
                if($geo['longitude']!==null){update_post_meta($post_id,'osint_longitude',(string)$geo['longitude']);}
                if(!empty($geo['geo_precision'])){update_post_meta($post_id,'osint_geo_precision',$geo['geo_precision']);}
            }
        }
    }
}

/**
 * AOSINT_Plugin — Singleton Orchestrator
 * يُهيئ جميع مكوّنات الإضافة عند plugins_loaded.
 */
final class AOSINT_Plugin{
    private static ?self $instance=null;
    private function __construct(){}
    public static function instance():self{if(null===self::$instance){self::$instance=new self();}return self::$instance;}
    public function run():void{AOSINT_Meta_Box::init();AOSINT_Save_Handler::init();}
    public static function on_activate():void{if(!get_option('aosint_installed_version')){update_option('aosint_installed_version',AOSINT_VERSION,false);update_option('aosint_install_date',current_time('mysql'),false);}}
    public static function on_deactivate():void{}
}
register_activation_hook(AOSINT_FILE,['AOSINT_Plugin','on_activate']);
register_deactivation_hook(AOSINT_FILE,['AOSINT_Plugin','on_deactivate']);
add_action('plugins_loaded',static function():void{AOSINT_Plugin::instance()->run();});
