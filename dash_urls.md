| Dash url    | IP          | Region     |
| :---        |    :---   |          :--- |
| http://www-itec.uni-klu.ac.at/ftp/datasets/mmsys12/BigBuckBunny/MPDs/BigBuckBunnyNonSeg_2s_isoffmain_DIS_23009_1_v_2_1c2_2011_08_30.mpd | 143.205.173.240 | Austria, Karnten |
| http://dash.akamaized.net/dash264/TestCases/1a/qualcomm/1/MultiRate.mpd | 23.56.3.42 | United States, California |
| https://livesim.dashif.org/livesim/chunkdur_1/ato_7/testpic4_8s/Manifest.mpd | 172.232.47.166 | France, Paris |



ffmpeg -loglevel 56 -i gozilla.mp4 -map 0 -map 0 -ss 10 -adaptation_sets "id=0,seg_duration=2,frag_duration=1,frag_type=duration,streams=v id=1,seg_duration=2,frag_type=none,streams=a" -f dash manifest.mpd
