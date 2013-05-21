<?php
require_once('settings.php');
class dinstarsms {
    public $state = array();
    public $prevstate = array();
    private $debug = false;

    private $run = true;
    function sig_handler($signo)
    {

         switch ($signo) {
             case SIGTERM:
                 // handle shutdown tasks
                 socket_close($this->client);
                 socket_close($this->tcp_socket);
                 exit;
                 break;
             case SIGHUP:
                 // handle restart tasks
                 break;
             case SIGUSR1:
                 echo "Caught SIGUSR1...\n";
                 break;
             default:
                 // handle all other signals
         }

    }
    function parse( $pkt ) {
        $header = array(
            'len' => unpack('N',substr($pkt,0,4)),
            'id' => array(
                'mac' => unpack('H*',substr($pkt,4,6)),
                'time' => unpack('N',substr($pkt,12,4)),
                'serial' => unpack('N',substr($pkt,16,4)),
            ),
            'type' => unpack('n',substr($pkt,20,2)),
            'flag' => unpack('n',substr($pkt,22,2)),
        );

        $header = array(
            'len' => $header['len'][1],
            'id' => array(
                'mac' => $header['id']['mac'][1],
                'time' => $header['id']['time'][1],
                'serial' => $header['id']['serial'][1],
            ),
            'type' => $header['type'][1],
            'flag' => $header['flag'][1],
        );

        switch($header['type']) {
            case 5:
                $body = array(
                    'number' => substr($pkt,24,24),
                    'type' => ord(substr($pkt,48,1)),
                    'port' => ord(substr($pkt,49,1)),
                    'timestamp' => substr($pkt,50,15),
                    'timezone' => ord(substr($pkt,65,1)),
                    'encoding' => ord(substr($pkt,66,1)),
                    'len' => unpack('n',substr($pkt,67,2)),
                    'content' => substr($pkt,69),
                );
                $body['len'] = $body['len'][1];
                if ( $body['encoding'] == 1 ) {
                    $body['content'] = utf8_encode($body['content']);
                    $body['content'] = str_replace("\0", "", $body['content']);
                }
                echo "new SMS from: ".$body['number']." content:".$body['content']." \n";
                if($this->debug)
                    print_r($body);
                $this->email($body['number'],$body['content']);
                return $this->send($header,6,chr(0));
                break;
            case 7:
                $body = array(
                    'count' => ord(substr($pkt,24,1))
                );
                for($i=0;$i<$body['count'];$i++) {
                    $body[$i] = ord(substr($pkt,25+$i,1));
                }

                $this->state = $body;

                if ( $this->prevstate != $this->state ) {
                    $this->prevstate = $this->state;
                    if($this->debug)
                        print_r($this->state);
                }
                if($this->debug){
                    print_r($header);
                    echo "\n";
                    print_r($body);
                }

                return $this->send($header,8,chr(0));
                break;
            case 15:
                //respond to login
                return $this->send($header,16,chr(0));
                break;
            default:
                if($this->debug){
                    $body = array(unpack('H*',substr($pkt,24)));
                    print_r($header);
                    print_r($body);
                }
                return true;
        }
    }

    function send($header,$type,$body) {
        /*
    Nov 17 07:36:29 dinstar.lan syslog: [216-07:36:28:730]00000002001FD6C706A10000429530DC00000405000700000100#015
    Nov 17 07:36:29 dinstar.lan syslog: [218-07:36:28:780]01000000001FD6C706A10000429530DC000004050800000000#015
    IN 00 00 00 02 00 1f d6 c7 06 a1 00 00 42 95 30 e7 00 00 04 3a 00 07 00 00 01 00 |
    UT 00 00 00 01 00 1f d6 c7 06 a1 00 00 42 95 30 e7 00 00 04 3a 00 08 00 00 00
    Nov 17 07:30:57 dinstar.lan syslog: [245-07:30:57:230]send received sms#015#012#015
    Nov 17 07:30:57 dinstar.lan syslog: [246-07:30:57:230]wia api:send data:#015
    Nov 17 07:30:57 dinstar.lan syslog: [247-07:30:57:230]00000002001FD6C706A1000042952EA1000001C2000700000100#015
    Nov 17 07:30:57 dinstar.lan syslog: [248-07:30:57:230]wia api:send data:#015
    Nov 17 07:30:57 dinstar.lan syslog: [249-07:30:57:230]00000035001FD6C706A1000042952EA1000001C30005000034363733333132313537380000000
    Nov 17 07:30:57 dinstar.lan syslog: [250-07:30:57:230]00010000085265737572736572#015
    Nov 17 07:30:57 dinstar.lan syslog: [251-07:30:57:280]wia api:recv data:#015
    Nov 17 07:30:57 dinstar.lan syslog: [252-07:30:57:280]01000000001FD6C706A1000042952EA1000001C20800000000#015
    Nov 17 07:30:58 dinstar.lan syslog: [253-07:30:57:480]wia api:recv data:#015
    Nov 17 07:30:58 dinstar.lan syslog: [254-07:30:57:480]01000000001FD6C706A1000042952EA1000001C30600000000#015
    Nov 17 07:30:58 dinstar.lan syslog: [255-07:30:57:480]delete recv msg, id=0#015
    Nov 17 07:31:00 dinstar.lan syslog: [000-07:30:59:330]peer close the socket#015#012#015
    Nov 17 07:31:00 dinstar.lan syslog: [001-07:30:59:330]read failed, close the socket#015#012#015
    */
        $pkt = pack('N',strlen($body));
        $pkt .= pack('H*',$header['id']['mac'])."\x00\x00";
        $pkt .= pack('N',$header['id']['time']);
        $pkt .= pack('N',$header['id']['serial']);
        $pkt .= pack('n',$type);
        $pkt .= pack('n',$header['flag']);
        $pkt .= $body;

        if($this->debug)
            print_r("UT ". $this->hex2ascii($pkt)."\n");

        if ( !$bytes = socket_write($this->client,$pkt) )
            return false;
        if($this->debug)
            echo "Sent $bytes bytes of ".strlen($pkt)."\n";
        return true;
    }
    function email($from,$text){
        $from = trim($from);
        $headers = "From: $from@sms.jonaz.net\r\n";
        $headers .= "Reply-To: $from@sms.jonaz.net\r\n";
        $headers .= "X-Mailer: PHP/".phpversion()."\r\n";
        $headers .= 'Content-type: text/html; charset=UTF-8' . "\r\n";
        mail(config::mailto,'New sms from '.$from,$text,$headers);
    }

    function __construct(){

        pcntl_signal(SIGTERM,array(&$this,"sig_handler")); 

        $this->tcp_socket = socket_create(AF_INET, SOCK_STREAM, getprotobyname('tcp'));
        socket_set_option($this->tcp_socket, SOL_SOCKET, SO_REUSEADDR, 1);
        if(!socket_bind($this->tcp_socket,'0.0.0.0',settings::port))
            die('failed to bind');
        socket_getsockname($this->tcp_socket,$ip,$p);
        socket_listen($this->tcp_socket,100);

        //socket_set_nonblock($this->tcp_socket);
        while( $this->run === true ) {
            echo "waiting for client to connect\n";
            $this->client = socket_accept($this->tcp_socket);  
            socket_set_nonblock($this->client);
            echo "client connected\n";
            $buff = '';
            $start = time();
            while(true){


                if($start < time()-45){
                    $header = array(
                        'len' =>0, 
                        'id' => array(
                            'mac' => '001fd6c706a1',
                            'time' => time(),
                            'serial' => 0,
                        ),
                        'flag' => 0,
                    );  
                    if(!$this->send($header,0,'')){
                        echo "sendbreak\n";
                        break;

                    }
                    $start = time();
                }
                $line = socket_read($this->client, 1024); 

                if(strlen($line) > 0 )
                    $buff .= $line;

                while ( $buff ) {
                    // Body length
                    $len = ord(substr($buff,0,1))*256*256*256;
                    $len += ord(substr($buff,1,1))*256*256;
                    $len += ord(substr($buff,2,1))*256;
                    $len += ord(substr($buff,3,1));

                    // Add header
                    $len += 24;

                    $pkt = substr($buff,0,$len);

                    if( strlen($pkt) == $len && strlen($pkt) > 23 ) {
                        $buff = substr($buff,$len);

                        if($this->debug){
                            print_r("len: ".strlen($pkt)."\n");
                            print_r( "IN ".$this->hex2ascii($pkt)."\n");
                        }
                        if(!$this->parse($pkt)){
                            echo "parsebreak\n";
                            break 2;
                        }
                    } else {
                        //print_r( "HALF ".$this->hex2ascii($pkt)." |  ".$this->hex2ascii($buff)."\n");
                        break;
                    }
                }
               usleep(100000);
            }
            echo "client disconnected\n";
            socket_close($this->client);
        }

        socket_close($this->client);
        socket_close($this->tcp_socket);
    }

    function hex2ascii($str)
    {
        $tmp = unpack("H*",$str);
        return $tmp[1];
        $p = '';
        for ($i=0; $i < strlen($str); $i=$i+1)
        {
            $tmp = dechex(ord(substr($str, $i, 1)));
            if(strlen($tmp) === 1 )
                $tmp = '0'.$tmp;
            $p .= ' '.$tmp;
        }
        return trim($p);
    }

}

$t = new dinstarsms();

?>
