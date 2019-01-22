module NFS;

export {
	redef enum Log::ID += {
		NFS_READDIR_LOG,
		NFS_READ_LOG,
		NFS_WRITE_LOG,
		NFS_LOOKUP_LOG		
	};

	type ReaddirInfo: record {
		ts		: time &log;
		id		: conn_id &log;
		uid		: string &log;
		dir_fh		: string &log;
		fname		: string &log;
		fh		: string &log;
	};
	
	type ReadInfo: record {
		ts		: time &log;
		id		: conn_id &log;
		uid		: string &log;
		fh		: string &log;
		offset		: count &log;
		size		: count &log;
		eof		: bool &log;
	};

	type WriteInfo: record {
		ts		: time &log;
		id		: conn_id &log;
		uid		: string &log;
		fh		: string &log;
		offset		: count &log;
		size		: count &log;
	};

	type LookupInfo: record {
		ts		: time &log;
		id		: conn_id &log;
		uid		: string &log;
		dir_fh		: string &log;
		fname		: string &log;
		fh		: string &log;
	};

}

const ports = {111/tcp, 111/udp, 2049/tcp, 2049/udp};

redef likely_server_ports += {ports};

event bro_init() &priority=5
	{
	Log::create_stream(NFS::NFS_READDIR_LOG, [$columns=NFS::ReaddirInfo, $path="nfs_readdir"]);
	Log::create_stream(NFS::NFS_READ_LOG, [$columns=NFS::ReadInfo, $path="nfs_read"]);
	Log::create_stream(NFS::NFS_WRITE_LOG, [$columns=NFS::WriteInfo, $path="nfs_write"]);
	Log::create_stream(NFS::NFS_LOOKUP_LOG, [$columns=NFS::LookupInfo, $path="nfs_lookup"]);
	

	Analyzer::register_for_ports(Analyzer::ANALYZER_NFS, ports);
	}

event nfs_proc_readdir(c: connection, info: NFS3::info_t, req: NFS3::readdirargs_t, rep: NFS3::readdir_reply_t)
	{
	local entries = rep$entries;

	for (i in entries)
		{
		local e = entries[i];
		local ent = NFS::ReaddirInfo($ts=network_time(), $id=c$id, $uid=c$uid, $dir_fh=req$dirfh,
						$fname=e$fname, $fh=e$fh);
		Log::write(NFS::NFS_READDIR_LOG, ent);
		}
	}

event nfs_proc_lookup(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::lookup_reply_t)
	{
    if (info$nfs_stat == NFS3::NFS3ERR_OK)
        {
	    local ent = NFS::LookupInfo($ts=network_time(), $id=c$id, $uid=c$uid, $dir_fh=req$dirfh,
		    			$fname=req$fname, $fh=rep$fh);
    	Log::write(NFS::NFS_LOOKUP_LOG, ent);
        }
	}

event nfs_proc_read(c: connection, info: NFS3::info_t, req: NFS3::readargs_t, rep: NFS3::read_reply_t)
	{
	local ent = NFS::ReadInfo($ts=network_time(), $id=c$id, $uid=c$uid, $fh=req$fh, $offset=req$offset,
					$size=rep$size, $eof=rep$eof);
	Log::write(NFS::NFS_READ_LOG, ent);
	}

event nfs_proc_write(c: connection, info: NFS3::info_t, req: NFS3::writeargs_t, rep: NFS3::write_reply_t)
	{
	local ent = NFS::WriteInfo($ts=network_time(), $id=c$id, $uid=c$uid, $fh=req$fh, $offset=req$offset,
					$size=req$offset);
	Log::write(NFS::NFS_WRITE_LOG, ent);
	}



