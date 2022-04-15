@load base/frameworks/sumstats
event zeek_init()
    {
      local r1 = SumStats::Reducer($stream="404.lookup", $apply=set(SumStats::SUM));
      local r2 = SumStats::Reducer($stream="404.uniq.lookup", $apply=set(SumStats::UNIQUE));
      local r3 = SumStats::Reducer($stream="connection.lookup", $apply=set(SumStats::SUM));
    
  
    SumStats::create([$name="find404",
                      $epoch=10mins,
                      $reducers=set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                      {
                    	local t1 = result["404.lookup"];
                    	local t2 = result["404.uniq.lookup"];
                   		local t3 = result["connection.lookup"];
                        local p1:double=(t3$sum)/(t3$sum);
                        local p2:double=((t2$unique)-1)/t3$sum;
                        if (t1$sum>2&&p1>0.2&&p2>0.5) 
                        {
                                print fmt("%s is a scanner with %.0f scan attemps on %d urls",key$host,t1$sum,(t2$unique)-1);
                        }
                      }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
{
	if(code==404)
	{
		SumStats::observe("404.lookup", SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
        SumStats::observe("404.uniq.lookup", SumStats::Key($host=c$id$orig_h),SumStats::Observation($str=c$http$uri));
	}
	else
	{
		SumStats::observe("404.lookup", SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=0));
        SumStats::observe("404.uniq.lookup", SumStats::Key($host=c$id$orig_h),SumStats::Observation($str="1"));
	}
	SumStats::observe("connection.lookup", SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
}
