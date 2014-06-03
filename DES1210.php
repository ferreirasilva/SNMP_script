<?php
class des1210meb2
{
    private $MAX_ACL_ID = 256;
    private $alias_oid = ".1.3.6.1.2.1.31.1.1.1.18";
    private $main_oid = ".1.3.6.1.4.1.171.10.75.15.2.14.10.3.1"; 
	private $check_ipm_oid = ".1.3.6.1.4.1.171.10.75.15.2.14.10.1.1"; 
	private $imb_oid = ".1.3.6.1.4.1.171.10.75.15.2.14.10.4.1"; 
	private $iface_oid = ".1.3.6.1.2.1.2.2.1";
	private $fdb_oid = ".1.3.6.1.2.1.17.7.1.2.2.1";
	private $acl_oid = ".1.3.6.1.4.1.171.10.75.15.2.15.3.1.1"; 
	private $profile_oid = ".1.3.6.1.4.1.171.10.75.15.2.15.1.2.1"; 
	private $cable_oid = ".1.3.6.1.4.1.171.10.75.15.2.35.1.1"; 
	private $arp_oid = ".1.3.6.1.2.1.4.22.1.2";
	private $loop_oid = ".1.3.6.1.2.1.158.1.3.1.1";
	private $link_oid = ".1.3.6.1.2.1.31.1.1.1.15";
	private $multi_oid = ".1.3.6.1.4.1.171.10.75.15.2.45"; 
	private $multi_vlan_oid = ".1.3.6.1.4.1.171.10.75.15.2.27.2.1"; 
	private $vlan_oid = ".1.3.6.1.4.1.171.10.75.15.2.7.6.1";
	private $ipif_oid = ".1.3.6.1.4.1.171.10.75.15.2.2";
	private $snmp_info_oid = ".1.3.6.1.2.1.1"; 
	private $dhcp_relay_oid = "1.3.6.1.4.1.171.10.75.15.2.28";




    /**************************************************************************************/
    //Update the port name of the switch 
    function update_portname($ip_switch, $names, $key_switch="private")
    {
        $soid = $this->alias_oid;
        $walk = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if (false === $walk) return (false);
        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
			$value = str_replace("\"", "", $value);
            if ((!isset($names[$oid])) or ($names[$oid] == $value)) continue (1);
            $res = snmp2_set($ip_switch, $key_switch, $soid.".".$oid, "s", $names[$oid]);
            if (true !== $res) return (false);
        }
        return (true);
    }

	/**************************************************************************************/
    //Create a IPMAC binding - have to find a better solution
    function add_imp($ip_switch, $ip_user, $mac_user, $port, $key_switch="private")
    {
        if ($ip_user == "0.0.0.0" || empty($ip_user)) return (false);
        if ($ip_switch == "0.0.0.0" || empty($ip_switch)) return (false);
        $mac_user = $this->ConvH2D(str_replace(":", "", str_replace("-", "", $mac_user))); 
        $soid = $this->main_oid;

        exec("snmpset -v2c -c ".$key_switch." ".$ip_switch." ".
            $soid.".4.4.".$ip_user.".".$mac_user. " i 5 1>/dev/null 2>/dev/null", $arr, $err); 
        if ($err > 0) return (false);
        exec("snmpset -v2c -c ".$key_switch." ".$ip_switch." ".
            $soid.".3.4.".$ip_user.".".$mac_user. " i {$port} 1>/dev/null 2>/dev/null", $arr, $err); 
        if ($err > 0) return (false);
        exec("snmpset -v2c -c ".$key_switch." ".$ip_switch." ".
            $soid.".4.4.".$ip_user.".".$mac_user. " i 1 1>/dev/null 2>/dev/null", $arr, $err); 
        if ($err > 0) return (false);

        return (true);

    }

	/**************************************************************************************/
    //Delete IPMAC binding
    function del_imp($ip_switch, $ip_user, $mac_user, $key_switch="private")
    {
        if ($ip_user == "0.0.0.0" || empty($ip_user)) return (false);
        if ($ip_switch == "0.0.0.0" || empty($ip_switch)) return (false);
		$mac_user = $this->ConvH2D(str_replace(":", "", str_replace("-", "", $mac_user)));
        return (true === snmp2_set($ip_switch, $key_switch, $this->main_oid.".4.4.".$ip_user.".".$mac_user, "i", 6));
    }


    /**************************************************************************************/
    //Delette IPMAC binding by MAC 
    function del_impm($ip_switch, $mac_user, $key_switch="private")
    {
        $soid = $this->main_oid.".2";
        if (false !== ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid)))
            foreach ($walk as $oid=>$value)
            {
                $ip = str_replace($soid.".", "", $oid);
                $mac = $this->text_to_mac($value);
                if ($mac == $mac_user)
                    return (true === snmp2_set($ip_switch, $key_switch, $this->main_oid.".4.".$ip, "i", 6));
            }
        return (false);
    }


    /**************************************************************************************/
    //Check IPMAC binding by IP
    function check_imp($ip_switch, $ip_user, $mac_user, $key_switch="private")
    {
		$soid = $this->main_oid . ".1";
        if (false !== ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid)))
        {
           foreach ($walk as $oid=>$value)
            {
                $ip = str_replace($soid.".4.", "", $oid);
                if (strpos($ip, $ip_user) !== false)
                    return (true);
            }
        }
        else return (false);
    }


    /**************************************************************************************/
    //Get the MAC address from IPMAC binding - By ip
    function get_imp_mac($ip_switch, $ip_user, $key_switch="private")
    {
        $soid = $this->main_oid.".2";
        if (false !== ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid)))
            foreach ($walk as $oid=>$value)
            {
                $ip = str_replace($soid.".4.", "", $oid);
                if (strpos($ip, $ip_user) !== false)
                    return ($this->text_to_mac(snmp2_get($ip_switch, $key_switch, $soid . ".4." . $ip)));
            }
        else return (false);
    }


    /**************************************************************************************/
    //Get the list of IPMAC binding
    function get_imp($ip_switch, $key_switch="private")
    {
        $result = array();
        $soid = $this->main_oid.".2";
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $ip_array = explode(".", str_replace($soid.".4.", "", $oid), -6);
            $ip = join(".", $ip_array);
            $mac = $this->text_to_mac($value);
            $result[$ip] = $mac;
        }
        return ($result);
    }

	/**************************************************************************************/
    //Get the list of IPMAC binding - By ports 
    function get_ipm_ports($ip_switch, $key_switch="private")
    {
        $soid = $this->main_oid.".3";
        $res = array();
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $ip = str_replace($soid.".4.", "", $oid);
            $res[$ip] = $value;
        }
        return ($res); 
    }

	/**************************************************************************************/
    //Get the status of IPMAC binding by ports
    function check_ipm_ports($ip_switch, $key_switch="private")
    {
        $state_array = array(0=>"disable", 1=>"enable");
        $soid = $this->check_ipm_oid.".2";
        $res = array();
        $walk = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if (false === $walk) return (false);
        foreach ($walk as $oid=>$value)
        {
            $port = str_replace($soid.".", "", $oid);
            $res[$port] = $state_array[$value];
        }
        return ($res);
    }

	/**************************************************************************************/
    //Set status of IPMAC binding - by ports
    function set_ipm_ports($ip_switch, $port, $state, $key_switch="private")
    {
        $state_array = array("disable"=>0, "enable"=>1);
        if (!isset($state_array[$state])) return (false);
        $soid = $this->check_ipm_oid.".2.".$port;
        return (true === snmp2_set($ip_switch, $key_switch, $soid, "i", $state_array[$state]));
    }

	/**************************************************************************************/
    //Get status IPMAC binding by blocked learning MAC
    function check_ipm_stop($ip_switch, $key_switch="private")
    {
        // There is no binding learning mode in this switch.
    }

	/**************************************************************************************/
    //Check blocked IPMAC binding by MAC
    function check_blocked_imp($ip_switch, $mac_user, $key_switch="private")
    {
        $soid = $this->imb_oid.".1";
        if (false !== ($walk = snmp2_walk($ip_switch, $key_switch, $soid)))
            foreach ($walk as $value)
            {
                $mac = $this->text_to_mac($value);
                if ($mac == $mac_user) return (true);
            }
        return (false);
    }

	/**************************************************************************************/
    //Get list of Blocked IPMAC
    function get_blocked_imp($ip_switch, $key_switch="private")
    {
        $soid = $this->imb_oid.".1";
        $result = false;
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $mac = $this->text_to_mac($value);
            $result[$mac] = 1;
        }
        return ($result);
    }

	/**************************************************************************************/
    //Delete blocked IPMAC binding by MAC
    function remove_block_imp($ip_switch, $mac_user, $key_switch="private")
    {
        $soid = $this->imb_oid.".5";
        if (false !== ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid)))
            foreach ($walk as $oid=>$value)
            {
                $mac_part = explode(".", str_replace($soid.".", "", $oid));
                $mac = sprintf("%02X:%02X:%02X:%02X:%02X:%02X", $mac_part[1], $mac_part[2], $mac_part[3], $mac_part[4], $mac_part[5], $mac_part[6]);
                if ($mac == $mac_user)
                    return (true === snmp2_set($ip_switch, $key_switch, $oid, "i", 1));
            }
        return (false);
    }

	/**************************************************************************************/
    //Get admin status of the ports
    function get_port_setting($ip_switch, $port, $key_switch="private")
    {
        $soid = $this->iface_oid.".7.".$port;
        return (snmp2_get($ip_switch, $key_switch, $soid));
    }

	/**************************************************************************************/
    //Get operational status of the ports
    function get_port_status($ip_switch, $port, $key_switch="private")
    {
        $soid = $this->iface_oid.".8.".$port;
        return (snmp2_get($ip_switch, $key_switch, $soid));
    }

	/**************************************************************************************/
    //enable/disable port - 1-up 2-down
    function set_port_state($ip_switch, $port, $state, $key_switch="private")
    {
        $soid = $this->iface_oid.".7.".$port;
        return (true === snmp2_set($ip_switch, $key_switch, $soid, "i", $state));
    }

	/**************************************************************************************/
    //enable/disable ports 
    function set_ports_state($ip_switch, $ports, $key_switch="private")
    {
        $states = array("up"=>1, "down"=>2);
        $soid = $this->iface_oid.".7";
        $walk = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if ((false === $walk) or (!is_array($walk))) return (false);
        foreach ($walk as $oid=>$st)
        {
            $port = str_replace($soid.".", "", $oid);
			if (!array_key_exists($port, $ports)) continue (1);
            if ((!isset($ports[$port])) or ((isset($states[$st])) and ($ports[$port] == $st))) continue(1);
            $res = snmp2_set($ip_switch, $key_switch, $soid.".".$port, "i", $ports[$port]);
            if (true !== $res) return (false);
        }
        return (true);
    }

	/**************************************************************************************/
    //Get list of FDB of the switch
    function get_fdb($ip_switch, $key_switch="private")
    {
        $soid = $this->fdb_oid.".2";
        $retval = array();
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
            $mac_part = explode(".", $oid);
            $mac = sprintf("%02X:%02X:%02X:%02X:%02X:%02X", $mac_part[1], $mac_part[2], $mac_part[3], $mac_part[4], $mac_part[5], $mac_part[6]);
            if (!empty($retval[$mac]))
            {
                if ($retval[$mac] != $value) $retval[$mac] .= ",".$value;
            }
            else $retval[$mac] = $value;
        }
        return ($retval);
    }

	/**************************************************************************************/
    //Get list of FDB per Vlan
    function get_fdb_vlan($ip_switch, $key_switch="private")
    {
        $soid = $this->fdb_oid.".2";
        $retval = array();
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
            $mac_part = explode(".", $oid);
            $mac = sprintf("%02X:%02X:%02X:%02X:%02X:%02X", $mac_part[1], $mac_part[2], $mac_part[3], $mac_part[4], $mac_part[5], $mac_part[6]);
            if (!empty($retval[$mac])) $retval[$mac] .= ",".$mac_part[0];
            else $retval[$mac] = $mac_part[0];
        }
        return ($retval);
    }

	/**************************************************************************************/
    //Search for a free acl : 0 if there is no free acl
    function get_free_acl($ip_switch, $profile_id, $key_switch="private")
    {
        $seen = array();
        $soid = $this->acl_oid.".1.".$profile_id;
        if (false !== ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid)))
            foreach ($walk as $value) $seen[$value] = 1;
        for ($i = 1; $i <= $this->MAX_ACL_ID; $i++)
            if (!isset($seen[$i])) return ($i);
        return (0);
    }

	/************************************************************************************ */
    //Get the list of acl as model:
    //[profile_id][acl_id] = array{params} 
    function get_acl_full($ip_switch, $key_switch="private")
    {
        $result = array();
        $params = array(
            8=>"src_ip",
            7=>"dst_ip",
            3=>"protocol",
            12=>"src_port",
            11=>"dst_port",
            25=>"permit",
            24=>"hex_port"
        );
        $soid = $this->acl_oid;
        $walk = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if ((false === $walk) or (!is_array($walk))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
            list($oid, $prof_id, $acl_id) = explode(".", $oid);
            if (isset($params[$oid])) $result[$prof_id][$acl_id][$params[$oid]] = str_replace("\"", "", str_replace(" ", "", $value));
        }
        return ($result);
    }


	/**************************************************************************************/
    //Create a ACL
	function make_acl($ip_switch, $profile_id, $acl_id, $params, $key_switch="private")
    {
        $soid = $this->acl_oid;
        $params_id = array(
            "src_ip"=>8,
            "dst_ip"=>7,
            "protocol"=>3,
            "src_port"=>12,
            "dst_port"=>11,
            "permit"=>25,
            "hex_port"=>24
        );
        $params_type = array(
            "src_ip"=>"a",
            "dst_ip"=>"a",
            "protocol"=>"i",
            "src_port"=>"i",
            "dst_port"=>"i",
            "permit"=>"i",
            "hex_port"=>"x"
        );
        $cmd = "";
        exec("snmpset -v2c -c " . $key_switch . " " . $ip_switch . " " . $soid . ".99." . $profile_id . "." . $acl_id . " i 5 1>/dev/null 2>/dev/null", $arr, $err);
        if ($err > 0){print("snmpset -v2c -c ".$key_switch." ".$ip_switch." ".$soid.".99.".$profile_id.".".$acl_id." i 5\n"); return (false);}
        foreach ($params as $k=>$value)
        {
            if (isset($params_id[$k])) $cmd = $soid.".".$params_id[$k].".".$profile_id.".".$acl_id." ".$params_type[$k]." '".$value."'";
            if (!empty($cmd))
            {
                exec("snmpset -v2c -c " . $key_switch . " " . $ip_switch . " " . $cmd . " 1>/dev/null 2>/dev/null", $arr, $err);
                if ($err > 0){print("snmpset -v2c -c ".$key_switch." ".$ip_switch." ".$cmd."\n"); return (false);}
            }
        }
        exec("snmpset -v2c -c " . $key_switch . " " . $ip_switch . " " . $soid . ".99." . $profile_id . "." . $acl_id . " i 1 1>/dev/null 2>/dev/null", $arr, $err);
        if ($err > 0){print("snmpset -v2c -c ".$key_switch." ".$ip_switch." ".$soid.".99.".$profile_id.".".$acl_id." i 1\n"); return (false);}
        return (true);
    }

	/**************************************************************************************/
    //Create a acl to block traffic based on IPaddress
	function create_acl($ip_switch, $ip_user, $profile_id, $port_user , $key_switch="private")
    {
        $acl_id = $this->get_free_acl($ip_switch, $profile_id, $key_switch);
        if (!$acl_id) return (false);

        $soid = $this->acl_oid;
        $port_user = $this->port2hash($port_user);
        $params = array(
                ".8." => " a {$ip_user} 1>/dev/null 2>/dev/null",
                ".24." => " x {$port_user} 1>/dev/null 2>/dev/null",
                ".25." => " i 2 1>/dev/null 2>/dev/null",
                ".99." => " i 1 1>/dev/null 2>/dev/null"
        );
        if(false === snmp2_set($ip_switch, $key_switch, $soid.".99.".$profile_id.".".$acl_id, "i", 5)) return (false);
        foreach($params as $key => $value) {
            exec("snmpset -v2c -c ".$key_switch." ".$ip_switch." ".$soid.$key.$profile_id.".".$acl_id.$value, $arr, $err);
            if($err > 0){
                snmp2_set($ip_switch, $key_switch, $soid.".99.".$profile_id.".".$acl_id, "i", 6);
                return (false);
            }
        }
		return (true);
    }

	/**************************************************************************************/
    //Search for a ACL
	function find_acl($ip_switch, $ip_user, $profile_id, $key_switch="private")
    {
        $retval = array();
        $soid = $this->acl_oid.".8.".$profile_id;
        if (false !== ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid)))
            foreach ($walk as $oid=>$value)
            {
                if ($ip_user == $value)
                {
                    $acl_id = str_replace($soid.".", "", $oid);
                    $soid = $this->acl_oid.".24.".$profile_id.".".$acl_id;
                    if (false !== ($port = snmp2_get($ip_switch, $key_switch, $soid)))
                    {
                        $port = str_replace(" ", "", str_replace("\"", "", $port));
                        $retval[$acl_id] = array($value, $port);
                        return ($retval);
                    }
                }
            }
        return (false);
    }

	/**************************************************************************************/
    //Delete ACL
	function delete_acl($ip_switch, $profile_id, $acl_id, $key_switch="private")
    {
        if (is_numeric($profile_id))
        {
            $soid = $this->acl_oid.".99.".$profile_id.".".$acl_id;
            return (true === snmp2_set($ip_switch, $key_switch, $soid, "i", "6"));
        }
        else
        {
            $ip_user = $profile_id;
            $profile_id = $acl_id;
            $found = $this->find_acl($ip_switch, $ip_user, $profile_id, $key_switch);
            if ($found)
            {
                $acl_id = key($found);
                $acl_ip = $found[$acl_id][0];
                $acl_port = $found[$acl_id][1];
                $soid = $this->acl_oid.".99.".$profile_id.".".$acl_id;
                return (true === snmp2_set($ip_switch, $key_switch, $soid, "i", "6"));
            }
            return (false);
        }
    }

	/* ********************************************************************************* */
    //Get ACL table
	function get_acl($ip_switch, $profile_id, $key_switch="private")
    {
        $retval = array();
        $soid = $this->acl_oid.".8.".$profile_id;
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $acl_id = str_replace($soid.".", "", $oid);
            $retval[$acl_id] = $value;
        }
        return ($retval);
    }

	/* ********************************************************************************* */
    //Get Blocked table. Returns: [ip]=array(ports) 
	function get_blocklist($ip_switch, $profile_id, $key_switch="private")
    {
        $retval = array();
        $soid = $this->acl_oid.".8.".$profile_id;
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $acl_id = str_replace($soid.".", "", $oid);
            $acls[$acl_id] = $value;
        }
        $deny = $this->acl_oid.".25.".$profile_id;
        if (false === ($swalk = snmp2_real_walk($ip_switch, $key_switch, $deny))) return (false);
        foreach ($swalk as $key=>$status)
        {
            if ($status === '2')
            {
				$acl_id = str_replace($deny.".", "", $key);
                $soid = $this->acl_oid.".24.".$profile_id;
                if (false === ($walk = snmp2_get($ip_switch, $key_switch, $soid.".".$acl_id))) return  (false);
                $retval[$acls[$acl_id]] = $this->hash2ports(str_replace("\"", "", str_replace(" ", "", $walk)));
            }
        }
        return ($retval);
    }

	/**************************************************************************************/
    //Get tge ACL profile lisr as model:
    //[profile_id] = array{params} 
	function get_ip_profiles_full($ip_switch, $key_switch="private")
    {
		$soid = $this->profile_oid;
        $walk = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if ((false === $walk) or (!is_array($walk))) return (false);
        $result = array();
        $params = array(
            4=>array(
                "1"=>"status_mask",
                "2"=>"status_tcp",
                "3"=>"status_udp",
                ),
			7=>"protocol",
			10=>"dst_mask",
            12=>"src_mask",
            13=>"port_dst_mask",
            14=>"port_src_mask",
        );

        $params_type = array (
			"status_mask"=>array(
				"00000200"=>"2",
				"00000400"=>"3",
				"00000600"=>"4",
			),
			"status_tcp"=>array(
				"00000800"=>"2",
				"00001000"=>"3",
				"00001800"=>"4"
			),
			"protocol"=>array(
				"0" => "1",
				"1" => "2",
				"2" => "3",
				"6" => "4",
				"17" => "5",
				"256" => "6"
			),
        );

        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
            list($oid, $id) = explode(".", $oid);
            $num = str_replace("\"", "", str_replace(" ", "", $value));
            if (isset($params[$oid]))
				{
					switch(true)
					{
						case($num === "00000200" || $num === "00000400" || $num === "00000600"): // veriry if it's ip address acl based
							$result[$id][$params[$oid]["1"]] = $params_type[$params[$oid]["1"]][$num];
							continue (1);
						case($num === "00000800" || $num === "00001000" || $num === "00001800"): // verify if it's port address acl based
							$result[$id][$params[$oid]["1"]] = "1";
							$status = $params_type[$params[$oid]["2"]][$num];
							continue (1);
						case($oid === "7"): // it is a little trick to make the status_udp/status_tcp
							$result[$id][$params[$oid]] = $params_type[$params[$oid]][$num];
							if ($num === "6") {
									$result[$id][$params["4"]["2"]] = $status;
									$result[$id][$params["4"]["3"]] = "1";
							} elseif ($num == "17") {
									$result[$id][$params["4"]["2"]] = "1";
									$result[$id][$params["4"]["3"]] = $status;
							}else {
									$result[$id][$params["4"]["2"]] = "1";
									$result[$id][$params["4"]["3"]] = "1";
							}
							continue (1);
						case($oid === "12" || $oid === "10"): // convert the hex ip address to dec ip address
							$result[$id][$params[$oid]] = $this->ConvH2D($num);
							continue (1);
						case($oid === "14" || $oid === "13"):
							$result[$id][$params[$oid]] = $num;
							continue (1);
						default: // put the status_mask as 1 (Unknown)
								$result[$id][$params[$oid]["1"]] = "1";
					}
				}
        }
        return ($result);
    }

	/**************************************************************************************/
    //Create a ACL profile
	function make_profile ($ip_switch, $profile_id, $params, $key_switch="private")
	{
        $soid = $this->profile_oid;
        $params_id = array(
            "status_mask"=>4,
            "src_mask"=>12,
            "dst_mask"=>10,
            "protocol"=>7,
            "status_tcp"=>4,
            "status_udp"=>4,
            "port_src_mask"=>14,
            "port_dst_mask"=>13,
        );
        $params_type = array(
            "status_mask"=>array(
                "2"=>"x 00000200",
                "3"=>"x 00000400",
                "4"=>"x 00000600"
                ),
            "src_mask"=>"x",
            "dst_mask"=>"x",
            "protocol"=>array(
                "1" => "i 0",
                "2" => "i 1",
                "3" => "i 2",
                "4" => "i 6",
                "5" => "i 17",
                "6" => "i 256"
                ),
            "status_tcp"=>array(
                "2"=>"x 00000800",
                "3"=>"x 00001000",
                "4"=>"x 00001800"
                ),
            "status_udp"=>array(
                "2"=>"x 00000800",
                "3"=>"x 00001000",
                "4"=>"x 00001800"
                ),
            "port_src_mask"=>"x",
            "port_dst_mask"=>"x",
        );

        if(false === snmp2_set($ip_switch, $key_switch, $soid.".30.".$profile_id, "i", "5")) return (false); // createandwait a access_profile
        if(false === snmp2_set($ip_switch, $key_switch, $soid.".2.".$profile_id, "i", "2")) return (false);	// specify layer 3 access_profile(IPv4)
        foreach ($params as $k=>$value) if (isset($params_id[$k]))
        {
            $cmd = "snmpset -v2c -c ".$key_switch." ".$ip_switch." ".$soid.".".$params_id[$k].".".$profile_id." ";
            switch ($k)
            {
                case ($k == "status_tcp" || $k == "status_udp" || $k == "status_mask" || $k == "protocol"):
                    exec($cmd.$params_type[$k][$value]." 1>/dev/null 2>/dev/null", $arr, $err);
                    continue(1);
                case ($k == "src_mask" || $k == "dst_mask"):
                    $ip = $this->ipD2H($value); // convert the ipaddress from dec to hex notation
                    exec($cmd.$params_type[$k]." ".$ip." 1>/dev/null 2>/dev/null", $arr, $err);
                    continue(1);
                default:
                    exec($cmd.$params_type[$k]." ".$value." 1>/dev/null 2>/dev/null", $arr, $err);
            }
        }
        if ($err > 0)
        {
            snmp2_set($ip_switch, $key_switch, $soid.".30.".$profile_id, "i", "6"); // delete the access_profile if some error occurred
            return (false);
        }
        if(false === snmp2_set($ip_switch, $key_switch, $soid.".30.".$profile_id, "i", "1")) return (false); // active the access_profile
        return (true);
    }

	/**************************************************************************************/
    //Delelte ACL profile
    function delete_profile($ip_switch, $profile_id, $key_switch="private")
    {
        $soid = $this->profile_oid.".30.".$profile_id;
        return (true === snmp2_set($ip_switch, $key_switch, $soid, "i", "6"));
    }

	/**************************************************************************************/
    //Get a list of ACL profile:
    //[profile_id] = profile_type
	//(1 - ethernet, 2 - IPv4, 3 - impb, 4 - arpSP_permit, 5 - arpSP_deny ,
	//	8 - aclQos, 9 - userDefined, 11 - IPv6, )
	function get_profiles($ip_switch, $key_switch="private")
    {
        $result = array();
        $soid = $this->profile_oid.".2";
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid => $profile)
        {
                $profile_id = str_replace($soid.".", "", $oid);
                $result[$profile_id] = $profile;
        }
        return ($result);
    }

	/**************************************************************************************/
    //Get the length of cable connected in the port
    // array [Number] => [status][length]
    // status:
    // 0-ok  1-open, 2-short, 3-open-short, 4-crosstalk, 5=>"unknown", 6=>"count", 7-no cable, 8-other
    function cable_test($ip_switch, $port, $key_switch="private")
    {
        $statuses = array(
			0=>"OK",
			1=>"open",
			2=>"short",
			3=>"open-short",
			4=>"crosstalk",
			5=>"unknown",
            6=>"count",
			7=>"no cable =",
			8=>"other"
			);

        $retval = array();
        $soid = $this->cable_oid.".12.".$port;
        if (true !== snmp2_set($ip_switch, $key_switch, $soid, "i", 1)) return (false);
        sleep(2);
        for ($i = 1; $i <= 4; $i++)
        {
            $soid = $this->cable_oid.".".($i + 3).".".$port;
            $status = snmp2_get($ip_switch, $key_switch, $soid);
            $soid = $this->cable_oid.".".($i + 7).".".$port;
            $l = snmp2_get($ip_switch, $key_switch, $soid);
            $retval[$i] = array($statuses[$status], $l);
        }
        return ($retval);
    }

	/**************************************************************************************/
    //Get the ARP table
    function get_arptable($ip_switch, $key_switch="private")
    {
        $retval = array();
        $soid = $this->arp_oid;
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
            $mac_part = explode(":", $value);
            $mac = sprintf("%02s:%02s:%02s:%02s:%02s:%02s", $mac_part[0], $mac_part[1], $mac_part[2], $mac_part[3], $mac_part[4], $mac_part[5]);
            $mac = strtoupper($mac);
            $ip = substr($oid, 3);
            if (!empty($retval[$mac])) $retval[$mac] .= ",".$ip;
            else $retval[$mac] = $ip;
        }
        return ($retval);
    }

	/**************************************************************************************/
    //Check the blocked port
    function get_block_status($ip_switch, $port, $key_switch="private")
    {
        $states = array("", "Normal", "Loop", "Error");
        $soid = $this->loop_oid.".".$port;
        if (false === ($s = snmp2_get($ip_switch, $key_switch, $soid))) return (false);
        if ($s > 2) $s = 3;
        return ($states[$s]);
    }

	/**************************************************************************************/
    //Get the link of the port (Highspeed) 
    function get_link_status($ip_switch, $port, $key_switch="private")
    {
        $links = array(0=>"down", 10=>"10M", 100=>"100M", 1000=>"1Г");
        $soid = $this->link_oid.".".$port;
        if (false === ($s = snmp2_get($ip_switch, $key_switch, $soid))) return (false);
        if ($s > 1000) return (false);
        return ($links[$s]);
    }

	/**************************************************************************************/
    //Transfer the configurations via TFTP
	function upload_cfg_to_tftp($ip_switch, $ip_tftp, $name, $key_switch="private")
    {
        if (!empty($ip_tftp))
        {
            $ip_tftp = ipD2H($ip_tftp);
        } else return (false);

        if (empty($ip_switch)) return (false);
        if (empty($name)) $name = "config/".$ip_switch.".cfg";

        $params = array(
                ".1.0 x " => $ip_tftp,
                ".4.0 s " => $name,
                ".5.0 i " => "2"
                );

        $soid = $this->file_oid;
        foreach ($params as $key => $value)
        {
                exec("snmpset -c private -v2c ".$ip_switch." ".$soid.$key.$value." 1>/dev/null 2>/dev/null", $arr, $err);
                if ( $err > 0 ) return (false);
        }

		$soid = $this->file_oid.".6.0";
        for ($i = 0; $i < 10; $i++)
        {
            usleep(500000);
            if (false === ($s = snmp2_get($ip_switch, $key_switch, $soid))) return (false);
            if ($s == 1) return true;
        }
        return (false);
    }

	/* ********************************************************************************* */
    //Add multicast profile in a port
	function add_multicast_port($ip_switch, $profile_id, $port, $key_switch="private")
    {
        $soid = $this->multi_oid.".3.1.4.1.".$port;
        if (false === ($mport = snmp2_get($ip_switch, $key_switch, $soid))) return false;
        $profiles = $this->hash2ports(str_replace(" ", "", trim($mport,"\"")));

        if (in_array($profile_id, $profiles)) return false;
        array_push($profiles, $profile_id);
        $addprofile = $this->numbers2hash($profiles);

        if (false === snmp2_set($ip_switch, $key_switch, $soid, "x", $addprofile)) return (false);

        return (true);
    }


	/* ********************************************************************************* */
    //Delete multicast profile from the port
	function del_multicast_port($ip_switch, $profile_id, $port, $key_switch="private")
    {
        $soid = $this->multi_oid.".3.1.4.1.".$port;
        if (false === ($mport = snmp2_get($ip_switch, $key_switch, $soid))) return false;
        $profiles = $this->hash2ports(str_replace(" ", "", trim($mport,"\"")));

        if (!in_array($profile_id, $profiles)) return false;
        $delprofile = $this->numbers2hash(array_diff($profiles, array($profile_id)));

        if (false === snmp2_set($ip_switch, $key_switch, $soid, "x", $delprofile)) return false;

        return (true);
    }

	/* ********************************************************************************* */
    //Get list of multicast profile in the ports
	function get_multicast_port($ip_switch, $key_switch="private")
    {
        snmp_set_quick_print(1);
        snmp_set_oid_numeric_print(1);
        $soid = $this->multi_oid.".3.1.4";
        $walk = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if (false === $walk) return (false);
        $result = array();
        foreach ($walk as $oid=>$value)
        {
            //print_r($walk);
            $port = str_replace($soid.".1.", "", $oid);
            $part = $this->hash2ports(str_replace(" ", "",trim($value, "\"")));
            foreach ($part as $id)  $result[trim($id)][$port] = 1;
        }
        return ($result);
    }

	/* ********************************************************************************* */
    //Get the number of the multicast VLAN 
	function get_mcast_vlan($ip_switch, $key_switch="private")
    {
        $vlan = false;
        $soid = $this->multi_vlan_oid.".1";
        $walk = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if (false === $walk) return (false);
        foreach ($walk as $oid=>$value)
         $vlan = $value;
        return $vlan;
    }

	/* ********************************************************************************* */
    //Update the replace_source_ip 
	function update_source_ip($ip_switch, $vlan, $source_ip, $key_switch="private")
    {
        $soid = $this->multi_vlan_oid.".8.".$vlan;
        $host = snmp2_get($ip_switch, $key_switch, $soid);
        if (false === $host) return (false);
        if ($host != $source_ip)
        {
            $res = snmp2_set($ip_switch, $key_switch, $soid, "a", $source_ip);
            if (false === $res) return (false);
            return ($host);
        }
        return (true);
    }

	/* ********************************************************************************* */
    //Update the multicast VLAN settings by ports 
	function update_multi_ports($ip_switch, $vlan, $ports, $key_switch="private")
    {
        $soid = $this->multi_vlan_oid;
        $res = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if ((false === $res) or (!is_array($res))) return (false);
        if ((!isset($res[$soid.".3.".$vlan])) or (!isset($res[$soid.".4.".$vlan])) or (!isset($res[$soid.".5.".$vlan]))) return (false);
        $real_source = str_replace("\"", "", str_replace(" ", "", $res[$soid.".3.".$vlan]));	//source_port
        $real_user = str_replace("\"", "", str_replace(" ", "", $res[$soid.".4.".$vlan]));		//member_port
        $real_tags = str_replace("\"", "", str_replace(" ", "", $res[$soid.".5.".$vlan]));		//tag_member_port
        $need_source = array();
        $need_user = array();
        $need_tags = array();
        foreach ($ports as $port=>$st)
            if ($st == 0) $need_source[] = $port;
            elseif ($st == 1) $need_user[] = $port;
            else $need_tags[] = $port;
        $need_source_hash = $this->numbers2hash($need_source);
        $need_user_hash = $this->numbers2hash($need_user);
        $need_tags_hash = $this->numbers2hash($need_tags);
        if (($need_source_hash != $real_source) or ($need_user_hash != $real_user) or ($need_tags_hash != $real_tags))
        {
            $clear = $this->numbers2hash(array());
            if (true !== snmp2_set($ip_switch, $key_switch, $soid.".3.".$vlan, "x", $clear)) return (false);
            if (true !== snmp2_set($ip_switch, $key_switch, $soid.".4.".$vlan, "x", $clear)) return (false);
            if (true !== snmp2_set($ip_switch, $key_switch, $soid.".5.".$vlan, "x", $clear)) return (false);
            if (true !== snmp2_set($ip_switch, $key_switch, $soid.".3.".$vlan, "x", $need_source_hash)) return (false);
            if (true !== snmp2_set($ip_switch, $key_switch, $soid.".4.".$vlan, "x", $need_user_hash)) return (false);
            if (true !== snmp2_set($ip_switch, $key_switch, $soid.".5.".$vlan, "x", $need_tags_hash)) return (false);
            return ("changed");
        }
        return (true);
    }

	/**************************************************************************************/
    //Get list of VLANs in the ports
	function get_vlans_to_port($ip_switch, $key_switch="private")
    {
        $retval = array("names"=>array(), "ports"=>array());
        $soid = $this->vlan_oid.".1";
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
            $retval["names"][$oid] = str_replace("\"", "", $value);
        }
        $soid = $this->vlan_oid.".2";
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
            $ports = $this->hash2ports(str_replace(" ", "", str_replace("\"", "", $value)));
            if (count($ports) > 0) foreach ($ports as $port) $retval["ports"][$oid][$port] = "tag";
        }
        $soid = $this->vlan_oid.".4";
        if (false === ($walk = snmp2_real_walk($ip_switch, $key_switch, $soid))) return (false);
        foreach ($walk as $oid=>$value)
        {
            $oid = str_replace($soid.".", "", $oid);
            $ports = $this->hash2ports(str_replace(" ", "", str_replace("\"", "", $value)));
            if (count($ports) > 0) foreach ($ports as $port) $retval["ports"][$oid][$port] = "untag";
        }
        return ($retval);
    }

	/**************************************************************************************/
    //Get the list of interfaces
	function get_ipifs($ip_switch, $key_switch="private")
    {
        $result = array();
        $result[1]["name"] = "System";
        $soid = $this->ipif_oid.".7.2.0";
        $ip = snmp2_get($ip_switch, $key_switch, $soid);
        $result[1]["ip"] = str_replace("\"", "", $ip);
        $soid = $this->ipif_oid.".7.3.0";
        $mask = snmp2_get($ip_switch, $key_switch, $soid);
        if (false === $mask) return (false);
        $result[1]["mask"] = str_replace("\"", "", $mask);
        $soid = $this->ipif_oid.".7.8.0";
        $vname = snmp2_get($ip_switch, $key_switch, $soid);
        $soid = $this->vlan_oid.".1";
        $vlans = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if (false === $vlans) return (false);
        foreach($vlans as $oid => $value)
        {
            if($value === $vname)
            {
                $vid = str_replace($soid.".", "", $oid);
                if ((false === $vid) or (!is_numeric($vid))) return (false);
                $result[1]["vid"] = $vid;
                return ($result);

            }
        }
    }

	/* ********************************************************************************* */
    //Update the DHCP_relay 
	function update_dhcp_relay($ip_switch, $enable, $hops, $time, $host, $key_switch="private")
    {
        $soid = $this->dhcp_relay_oid.".2.1.1.3.6.83.121.115.116.101.109";
        $walk = snmp2_real_walk($ip_switch, $key_switch, $soid);
        if ((false === $walk) or (!is_array($walk))) return (false);
        $need = 1;
        foreach ($walk as $oid=>$value)
        {
            $real_host = str_replace($soid.".", "", $oid);
            if ($real_host != $host)
            {
                if (true !== snmp2_set($ip_switch, $key_switch, $soid.".".$real_host, "i", 6)) return (false);
                $old_host = $real_host;
            }
            else $need = 0;
        }
        if ($need)
        {
            $res = snmp2_set($ip_switch, $key_switch, $soid.".".$host, "i", 4);
            if (false === $res) return (false);
            elseif (count($walk) > 0) return ($old_host);
        }
        return (true);
    }

	/**************************************************************************************/
    //Convert MAC from hex to dec notation 
	function ConvH2D ($mac)
	{
		$result = '';
		while (strlen($mac) > 0) {
			$sub = substr($mac, 0, 2);
			$result .= hexdec($sub) . ".";
			$mac = substr($mac, 2, strlen($mac));
		}
		return ($result = substr($result, 0, strlen($result) - 1));
	}

	/**************************************************************************************/
    //Convert text to mac address notation
    function text_to_mac($value)
    {
        $mac = "";
        if (strlen($value) < 15) for ($i = 1; $i < strlen($value)-1; $i++)
        {
            if ($value[$i] == "\\") $i++;
            if (!empty($mac)) $mac .= ":".sprintf("%02X", ord($value[$i]));
            else $mac = sprintf("%02X", ord($value[$i]));
        }
        else $mac = str_replace(" ", ":", trim(str_replace("\"", "", $value)));
        return ($mac);
    }

	/**************************************************************************************/
    //Convert port number in hex notation 
	function port2hash($port)
    {
        if ($port < 32)
        {
            $hash = 0x100000000/pow(2, $port);
            return (sprintf("%08X", $hash));
        }
        else
        {
            $hash = 0x10000000000000000/pow(2, $port);
            return (sprintf("%016X", $hash));
        }
    }

	/**************************************************************************************/
    //Convert numbers in hash
	public function numbers2hash($numbers)
    {
        $hash_all = "";
        foreach ($numbers as $number)
        {
            if ($number < 32) $hash = "0x".sprintf("%08X", 0x100000000/pow(2, $number)) + 0 ;
            else return false;
            $hash_all = $hash_all ^ $hash;
        }
        return (sprintf("%08X", $hash_all));
    }

	/**************************************************************************************/
    //Convert hash to ports
    function hash2ports($hash)
    {
        if (strlen($hash) > 8) $param = 0x10000000000000000;
        else $param = 0x100000000;
        $hash = "0x".$hash;
        $ports = array();
        $num = 1;
        while ($hash > 0)
        {
            if (($hash - $param/pow(2, $num)) >= 0)
            {
                $ports[] = $num;
                $hash = $hash - $param/pow(2, $num);
            }
            $num++;
        }
        return ($ports);
    }

	/**************************************************************************************/
    //Convert IP from dec to hex notation 
	function ipD2H($ip) {
        $ip_part = explode(".", $ip);
        $ip_hex  = sprintf("%02X%02X%02X%02X", $ip_part[0], $ip_part[1], $ip_part[2], $ip_part[3]);
        return $ip_hex;
	}




}





