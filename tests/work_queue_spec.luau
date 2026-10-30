local WorkQueue = require("../work-queue")

local function clock()
    local state = { time = 0, calls = 0, timers = {} }
    local api = {}
    function api.now()
        state.calls = state.calls + 1
        return state.time
    end
    function api.timer(ms, callback)
        state.calls = state.calls + 1
        assert(ms >= 0, "negative timer delay")
        local handle = { due = state.time + ms, callback = callback, active = true }
        function handle:cancel()
            state.calls = state.calls + 1
            self.active = false
        end
        table.insert(state.timers, handle)
        return handle
    end
    function state:active()
        local count = 0
        for _, handle in ipairs(self.timers) do
            if handle.active then count = count + 1 end
        end
        return count
    end
    -- One host timer dispatch, never a drain loop: each tick has its own cx.
    function state:tick(cx)
        local nextTimer = nil
        for _, handle in ipairs(self.timers) do
            if handle.active and handle.due <= self.time
                and (not nextTimer or handle.due < nextTimer.due) then
                nextTimer = handle
            end
        end
        if not nextTimer then return false end
        nextTimer.active = false
        nextTimer.callback(cx)
        assert(self:active() <= 1, "more than one live queue timer")
        return true
    end
    return state, api
end

local function fixture()
    local time, api = clock()
    local state = { generation = 1, errors = {} }
    state.time = time
    state.queue = WorkQueue.new(api, function(token)
        return token == state.generation
    end, function(cx, message)
        table.insert(state.errors, { cx = cx, message = message })
    end)
    return state
end

local cases = {}

function cases.delivery_is_deferred_and_uses_fresh_context()
    local f = fixture()
    local calls = {}
    local first, second = {}, {}
    f.queue:post(1, function(cx) table.insert(calls, cx) end)
    f.queue:post(1, function(cx) table.insert(calls, cx) end)
    f.queue:wake()
    assert(#calls == 0 and f.time:active() == 1)
    assert(f.time:tick(first))
    assert(#calls == 1 and calls[1] == first and f.time:active() == 1)
    assert(f.time:tick(second))
    assert(#calls == 2 and calls[2] == second and f.time:active() == 0)
end

function cases.receipt_only_stores_first_result()
    local f = fixture()
    local result, delivered, fresh = {}, 0, {}
    local receipt = f.queue:wait(1, 500, function(value, cx, timedOut)
        assert(value == result and cx == fresh and timedOut == false)
        delivered = delivered + 1
    end)
    local calls = f.time.calls
    receipt(result)
    receipt({ ignored = true })
    assert(f.time.calls == calls and delivered == 0, "receipt performed work")
    f.time.time = 50
    assert(f.time:tick(fresh))
    assert(delivered == 1 and f.time:active() == 0)
    receipt({ late = true })
    f.queue:wake()
    assert(not f.time:tick({}) and delivered == 1)
end

function cases.explicit_wake_accelerates_receipt_without_duplicate_timer()
    local f = fixture()
    local delivered = 0
    local receipt = f.queue:wait(1, 1000, function()
        delivered = delivered + 1
    end)
    receipt("ready")
    f.queue:wake()
    f.queue:wake()
    assert(f.time:active() == 1 and delivered == 0)
    assert(f.time:tick({}))
    f.time.time = 1000
    assert(not f.time:tick({}))
    assert(delivered == 1 and f.time:active() == 0)
end

function cases.wake_rearms_due_timer_and_ignores_cancelled_dispatch()
    local f = fixture()
    local fresh, delivered = {}, 0
    f.queue:post(1, function(cx)
        assert(cx == fresh)
        delivered = delivered + 1
    end)
    local loadTimer = f.time.timers[1]
    f.queue:wake()
    assert(not loadTimer.active and f.time:active() == 1)
    loadTimer.callback({ staleContext = true })
    assert(delivered == 0 and f.time:active() == 1)
    assert(f.time:tick(fresh) and delivered == 1 and f.time:active() == 0)
end

function cases.stale_enqueue_cancels_timer_after_pruning_last_job()
    local f = fixture()
    f.queue:post(1, function() error("stale work ran") end)
    f.generation = 2
    f.queue:post(1, function() error("stale work ran") end)
    assert(f.time:active() == 0 and #f.errors == 0)
end

function cases.nil_receipt_is_not_a_timeout()
    local f = fixture()
    local delivered = 0
    local receipt = f.queue:wait(1, 100, function(value, _, timedOut)
        assert(value == nil and timedOut == false)
        delivered = delivered + 1
    end)
    receipt(nil)
    f.queue:wake()
    assert(f.time:tick({}) and delivered == 1)
end

function cases.timeout_is_exact_and_late_receipt_cannot_redeliver()
    local f = fixture()
    local delivered, fresh = 0, {}
    local receipt = f.queue:wait(1, 40, function(value, cx, timedOut)
        assert(value == nil and cx == fresh and timedOut == true)
        delivered = delivered + 1
    end)
    f.time.time = 39
    assert(not f.time:tick({}) and delivered == 0)
    f.time.time = 40
    assert(f.time:tick(fresh) and delivered == 1)
    local calls = f.time.calls
    receipt("too late")
    assert(f.time.calls == calls)
    f.queue:wake()
    f.time.time = 200
    assert(not f.time:tick({}) and delivered == 1 and f.time:active() == 0)
end

function cases.receipt_present_before_timeout_dispatch_wins()
    local f = fixture()
    local delivered = 0
    local receipt = f.queue:wait(1, 40, function(value, _, timedOut)
        assert(value == "arrived" and timedOut == false)
        delivered = delivered + 1
    end)
    -- Receipt callbacks deliberately cannot consult a clock during a hook pause.
    f.time.time = 100
    receipt("arrived")
    assert(f.time:tick({}) and delivered == 1)
end

function cases.stale_generation_drops_jobs_and_cancels_idle_timer()
    local f = fixture()
    local receipt = f.queue:wait(1, 100, function() error("stale receipt ran") end)
    f.queue:post(1, function() error("stale post ran") end)
    f.generation = 2
    f.queue:wake()
    assert(f.time:active() == 0)
    receipt("stale")
    f.queue:post(1, function() error("new stale post ran") end)
    assert(f.time:active() == 0)
    local delivered = 0
    f.queue:post(2, function() delivered = delivered + 1 end)
    assert(f.time:tick({}) and delivered == 1 and #f.errors == 0)
end

function cases.timer_checks_generation_without_explicit_wake()
    local f = fixture()
    f.queue:post(1, function() error("stale action ran") end)
    f.generation = 2
    assert(f.time:tick({}))
    assert(f.time:active() == 0 and #f.errors == 0)
end

function cases.waiting_receipt_does_not_block_reconciliation()
    local f = fixture()
    local order = {}
    local receipt = f.queue:wait(1, 100, function()
        table.insert(order, "receipt")
    end)
    f.queue:post(1, function() table.insert(order, "reconcile") end)
    assert(f.time:tick({}) and #order == 1 and order[1] == "reconcile")
    receipt(true)
    f.queue:wake()
    assert(f.time:tick({}) and #order == 2 and order[2] == "receipt")
end

function cases.successor_is_prearmed_and_survives_action_exception()
    local f = fixture()
    local actionCx, reconcileCx = {}, {}
    local reconciled = false
    local observedCx, armedDuringAction
    f.queue:post(1, function(cx)
        observedCx = cx
        armedDuringAction = f.time:active()
        error("credential=must-not-escape")
    end)
    f.queue:post(1, function(cx)
        assert(cx == reconcileCx)
        reconciled = true
    end)
    assert(f.time:tick(actionCx))
    assert(observedCx == actionCx and armedDuringAction == 1, "successor not prearmed")
    assert(not reconciled and f.time:active() == 1 and #f.errors == 1)
    assert(f.errors[1].cx == actionCx)
    assert(f.errors[1].message == "TURN work action was interrupted; queued reconciliation will continue.")
    assert(f.time:tick(reconcileCx) and reconciled and f.time:active() == 0)
end

function cases.successor_posted_inside_action_survives_exception()
    local f = fixture()
    local reconciled = false
    local armedDuringAction
    f.queue:post(1, function()
        f.queue:post(1, function() reconciled = true end)
        armedDuringAction = f.time:active()
        error("native action failed")
    end)
    assert(f.time:tick({}) and not reconciled)
    assert(armedDuringAction == 1, "posted successor not prearmed")
    assert(f.time:tick({}) and reconciled and #f.errors == 1)
end

function cases.queue_capacity_is_bounded_and_stale_jobs_release_capacity()
    local f = fixture()
    for _ = 1, 64 do
        f.queue:post(1, function() error("stale work ran") end)
    end
    local ok = pcall(function() f.queue:post(1, function() end) end)
    assert(not ok and f.time:active() == 1)
    f.generation = 2
    local delivered = false
    f.queue:post(2, function() delivered = true end)
    assert(f.time:tick({}) and delivered and #f.errors == 0)
end

local function run()
    local passed = 0
    for name, test in pairs(cases) do
        local ok, err = pcall(test)
        assert(ok, name .. ": " .. tostring(err))
        passed = passed + 1
    end
    return passed
end

return { run = run }
