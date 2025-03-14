$(document).ready(function () {
    // Initialize DataTable if it exists
    if ($("#activityTable").length) {
        var table = $("#activityTable").DataTable();
    }

    // Connect to WebSocket Server
    var socket = io.connect("http://127.0.0.1:5000", {
        transports: ["websocket"],
        reconnection: true,
        reconnectionAttempts: 10,
        reconnectionDelay: 2000
    });

    socket.on("connect", function () {
        console.log("✅ Connected to WebSocket!");
    });

    socket.on("connect_error", function (error) {
        console.error("❌ WebSocket Connection Error:", error);
    });

    socket.on("disconnect", function () {
        console.warn("⚠️ Disconnected from WebSocket. Attempting to reconnect...");
    });

    socket.on("new_log", function (log) {
        console.log("📡 Received new log:", log);

        if (table) {
            table.row.add([log.user, log.action, log.time, log.risk]).draw();
        }

        // Update risk statistics
        let highRisk = parseInt($("#highRiskCount").text()) || 0;
        let moderateRisk = parseInt($("#moderateRiskCount").text()) || 0;
        let lowRisk = parseInt($("#lowRiskCount").text()) || 0;

        if (log.risk === "High") highRisk++;
        else if (log.risk === "Medium") moderateRisk++;
        else lowRisk++;

        $("#highRiskCount").text(highRisk);
        $("#moderateRiskCount").text(moderateRisk);
        $("#lowRiskCount").text(lowRisk);
    });

    // Fetch initial data from API
    fetch("http://127.0.0.1:5000/api/realtime-data")
        .then(response => response.json())
        .then(data => {
            if (data.status === "success" && table) {
                data.logs.forEach(log => {
                    table.row.add([log.user, log.action, log.time, log.risk]).draw();
                });
            }
        })
        .catch(error => console.error("❌ Error fetching logs:", error));

    // Section Switching
    $(".nav-link").click(function (event) {
        event.preventDefault();

        let targetSection = $(this).data("section");

        // Hide all sections and show the selected one
        $(".content-section").addClass("d-none");
        $("#" + targetSection).removeClass("d-none");

        // Update active class in sidebar
        $(".nav-link").removeClass("active");
        $(this).addClass("active");
    });

    // Show the default section (Dashboard) on page load
    $(".content-section").addClass("d-none");
    $("#dashboard").removeClass("d-none");
});
