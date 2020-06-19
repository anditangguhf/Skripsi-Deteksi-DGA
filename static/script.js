jQuery(document).ready(function ($) {

    // $(".datatables").DataTable();
    $(".domains-overview.table-upload").DataTable();
    $(".domains-overview.table-history").DataTable();
    $(".domains-overview.table-all-history").DataTable({
        order: [1, 'desc']
    });

    $(".show-log").click(function () {
        var $log = $(".capture-log").removeClass("hidden");
    });

    var URL = window.location.href;
    var PATHNAME = window.location.pathname;
    // console.log(URL);
    // console.log(PATHNAME);

    $(".reload-page").click(function() {
        window.location.reload();
        return false;
    });

    if(PATHNAME === "/live") {
        /* LIVE CAPTURE */

        var liveObj = {};

        var socket = io.connect('http://localhost:5000/');

        socket.on('connect', function () {
            socket.send("Connected");
        })

        // callback from app.py
        socket.on('capture', function (msg) {
            // console.log("Capture msg: " + msg);
            var $log = $(".capture-log .log-capture");
            var m = JSON.parse(msg);
            switch (m['type']) {
                case 'start':
                    liveObj['start_time'] = m['value'];
                    liveObj['start_time_readable'] = timestamp_to_datetime(m['value'].split("_"));
                    $log.append("<div>Capturing packets starts on: " + liveObj['start_time_readable'] + "</div>");
                    break;
                case 'end':
                    var table = $(".domains-overview.table-live").DataTable();
                    liveObj['end_time'] = m['end_time'];
                    liveObj['end_time_readable'] = timestamp_to_datetime(m['end_time'].split("_"));
                    $log.append("<div>Capturing packets ends on: " + liveObj['end_time_readable'] + "</div>");
                    $log.append("<div>=========</div>");
                    $log.append("<div>Total analyzed domains: " + m['summary'].length + "</div>");
                    var total_dga = 0;
                    $.each(m['summary'], function (k, v) {
                        if(v['is_dga'] === 1) {
                            is_dga = "DGA";
                            total_dga++;
                        } else {
                            is_dga = "Valid/Non-DGA";
                        }
                        var total_queries = v['packet_ids'].length;
                        table.row.add([v['id'], v['name'], v['count_nxdomain'], total_queries, is_dga, "<a href='" + URL + "/details/" + m['start_time'] + "/" + v['id'] + "'><button class='btn btn-info btn-sm' type='button'>Details</button></a>"]).draw();
                    });
                    $log.append("<div>Total DGA domains: " + total_dga + "</div>");

                    // close socket
                    socket.close()
                    break;
            }

            console.log(liveObj);
        });

        $(".start-capture").click(function () {
            $(this).prop("disabled", true);
            $(".stop-capture").removeAttr("disabled");
            console.log("click start");

            var act = { 'act': 'start' };

            socket.send(JSON.stringify(act));
        });

        $(".stop-capture").click(function () {
            $(this).prop("disabled", true);
            $(".reload-page").removeAttr("disabled");
            console.log("click stop");

            var act = { 'act': 'end' };

            socket.send(JSON.stringify(act));
        });
    }

    /* UPLOAD PCAP */

    $(".upload-pcap").change(function () {
        file = this.files[0]
        console.log(file);
        console.log(file.name);

        var parent = $(this).closest('.row');
        var spinner = $(".dummy-spinner").clone().removeClass("dummy-spinner hidden").appendTo(parent);

        var $log_area = $(".log-area.log-upload");
        $log_area.empty();

        // $(".capture-log").removeClass("hidden");
        var log = "<div>Uploading PCAP file: " + file.name + "</div>"
        $log_area.append(log);

        // pake form data kirim pake ajax ke routes
        var formData = new FormData();
        formData.append("pcap", this.files[0]);

        var table = $(".domains-overview.table-upload").DataTable();
        // var table = $(".domains-overview.table-upload");
        table.clear().draw();

        $.ajax({
            url: 'http://localhost:5000/uploader',
            type: 'post',
            data: formData,
            contentType: false,
            processData: false,
            success: function (res) {
                res = JSON.parse(res);
                console.log(res);
                if(res['status'] === -1) {
                    $log_area.append("<div>" + res['msg'] + "</div>");
                } else {
                    let total_dga = 0;
                    let is_dga = "";
                    $.each(res['summary'], function (k, v) {
                        if(v['is_dga'] === 1) {
                            is_dga = "DGA";
                            total_dga++;
                        } else {
                            is_dga = "Valid/Non-DGA";
                        }
                        var total_queries = v['packet_ids'].length;
                        table.row.add([v['id'], v['name'], v['count_nxdomain'], total_queries, is_dga, "<a href='" + URL + "/details/" + res['timestamp'] + "/" + v['id'] + "'><button class='btn btn-info btn-sm' type='button'>Details</button></a>"]).draw();
                    });
                    let timestamp = res['timestamp'].split("_");
                    let newDate = timestamp_to_datetime(timestamp);

                    $log_area.append("<div>Saved as: " + res['filename'] + "</div>");
                    $log_area.append("<div>Uploaded and Analyzed on: " + newDate + "</div>");
                    $log_area.append("<div>DNS Packets captured from: " + res['first_packet_time'] + " to: " + res['last_packet_time'] + "</div>");
                    $log_area.append("<div>Total analyzed domains: " + res['summary'].length + "</div>");
                    $log_area.append("<div>Total DGA domains: " + total_dga + "</div>");
                }
                spinner.remove();
            }
        })
    });

    function timestamp_to_datetime(timestamp) {
        var date = timestamp[0];
        var time = timestamp[1];

        var year = date.slice(0,4);
        var month = date.slice(4,6);
        var date = date.slice(6,8);

        var hour = time.slice(0,2);
        var minute = time.slice(2,4);
        var second = time.slice(4,6);
        var milisecond = time.slice(6,8);

        var newDate = new Date(year, month, date, hour, minute, second, milisecond);
        return newDate;
    }

    $(".pcap-history-picker").change(function () {
        var parent = $(this).closest('.form-group');
        var spinner = $(".dummy-spinner").clone().removeClass("dummy-spinner hidden").appendTo(parent);
        var table = $(".domains-overview.table-history").DataTable();
        // var table = $(".domains-overview.table-history");
        var $log_area = $(".log-area.log-history");
        $log_area.empty();
        table.clear().draw();
        var value = $(this).val();
        $.ajax({
            url: 'http://localhost:5000/_history',
            type: 'post',
            data: {
                'val': value
            },
            success: function (res) {
                res = JSON.parse(res);
                console.log(res);
                let total_dga = 0;
                let is_dga = "";
                $.each(res['summary'], function (k, v) {
                    var href = URL + '/details/' + res['timestamp'] + '/' + v['id'];
                    if(v['is_dga'] === 1) {
                        is_dga = "DGA";
                        total_dga++;
                    } else {
                        is_dga = "Valid/Non-DGA";
                    }
                    var total_queries = v['packet_ids'].length;
                    table.row.add([v['id'], v['name'], v['count_nxdomain'], total_queries, is_dga, "<a href='" + href + "'><button" +
                    " class='btn" +
                    " btn-info btn-sm'" +
                    " type='button'>Details</button></a>"]).draw();
                });
                let timestamp = res['timestamp'].split("_");
                let newDate = timestamp_to_datetime(timestamp);
                if(res['prefix'] === "capture") {
                    $log_area.append("<div>Viewing live capture history of: " + newDate + "</div>");
                } else if(res['prefix'] === "upload") {
                    $log_area.append("<div>Viewing upload pcap history of: " + res['filename'] + "</div>");
                    $log_area.append("<div>Uploaded and Analyzed on: " + newDate + "</div>");
                }
                $log_area.append("<div>DNS Packets captured from: " + res['first_packet_time'] + " to: " + res['last_packet_time'] + "</div>");
                $log_area.append("<div>Total analyzed domains: " + res['summary'].length + "</div>");
                $log_area.append("<div>Total DGA domains: " + total_dga + "</div>");
                spinner.remove();
            }
        })
    });

    $(".btn-refresh").click(function () {
        var parent = $(this).closest(".refresh-container");
        var spinner = $(".dummy-spinner").clone().removeClass("dummy-spinner hidden").appendTo(parent);
        var table = $(".domains-overview.table-all-history").DataTable();
        // var table = $(".domains-overview.table-all-history");
        var prefix = $(this).attr("table-prefix");
        var $log_area = $(".log-area.log-all-history");
        $log_area.empty();
        table.clear().draw();
        $.ajax({
            url: 'http://localhost:5000/_all_history',
            type: 'post',
            data: {
                'prefix': prefix
            },
            success: function (res) {
                console.log(res)
                let filenames = []
                let total_domains = 0;
                let total_dga = 0;
                $.each(res, function(k, v) {
                    var filename = k;
                    if(prefix === "capture_") {
                        filename = timestamp_to_datetime(k.split("_"));
                    }
                    filenames.push(filename);
                    var timestamp = v['timestamp'];
                    total_domains += v['summary'].length;
                    $.each(v['summary'], function(vk, vv) {
                        var href = URL + '/details/' + timestamp + '/' + vv['id'];
                        if(vv['is_dga'] === 1) {
                            is_dga = "DGA";
                            total_dga++;
                        } else {
                            is_dga = "Valid/Non-DGA";
                        }
                        var total_queries = JSON.parse(vv['packet_ids']).length;
                        table.row.add([vv['id'], filename, vv['name'], vv['count_nxdomain'], total_queries, is_dga, "<a href='"+href+"'><button class='btn btn-info" +
                        " btn-sm'" +
                        " type='button'>Details</button></a>"]).draw();
                    })
                });
                $log_area.append("<div>Viewing histories of: </div>");
                let num = 0;
                $.each(filenames, function(k,v) {
                    num = k + 1;
                    $log_area.append("<div>" + num + ". " + v + "</div>");
                })
                $log_area.append("<div>==========</div>");
                $log_area.append("<div>Total analyzed domains: " + total_domains + "</div>");
                $log_area.append("<div>Total DGA domains: " + total_dga + "</div>");
                spinner.remove();
            }
        })
    });
});
