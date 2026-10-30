-- A receipt only stores its result. All continuations run in fresh timer contexts.
local POLL_MS = 50
local MAX_PENDING = 64
local ACTION_ERROR = "TURN work action was interrupted; queued reconciliation will continue."

local function new(api, isCurrent, onError)
    local jobs = {}
    local timer = nil
    local runner = {}
    local tick

    local function close(job)
        job.closed = true
        job.result = nil
        job.callback = nil
    end

    local function prune()
        for index = #jobs, 1, -1 do
            if not isCurrent(jobs[index].token) then
                close(table.remove(jobs, index))
            end
        end
    end

    function runner:wake()
        prune()
        if #jobs == 0 then
            if timer then
                local previous = timer
                timer = nil
                previous.handle:cancel()
            end
            return
        end
        local now = api.now()
        local due = now + POLL_MS
        for _, job in ipairs(jobs) do
            if job.received then
                due = now
                break
            end
            due = math.min(due, math.max(now, job.deadline))
        end
        -- Re-arm even a due timer: wake may move load-time work to an owner context.
        if timer then
            local previous = timer
            timer = nil
            previous.handle:cancel()
        end
        local nextTimer = {}
        timer = nextTimer
        nextTimer.handle = api.timer(due - now, function(cx)
            if timer ~= nextTimer then return end
            timer = nil
            tick(cx)
        end)
    end

    tick = function(cx)
        prune()
        local now = api.now()
        local selected = nil
        for index, job in ipairs(jobs) do
            if job.received or now >= job.deadline then
                selected = table.remove(jobs, index)
                break
            end
        end
        local callback, result, timedOut
        if selected then
            callback = selected.callback
            result = selected.result
            timedOut = not selected.received
            close(selected)
        end
        -- Arm first: native calls may abort the hook before any subsequent line runs.
        runner:wake()
        if callback then
            local ok
            if selected.waiting then
                ok = pcall(callback, result, cx, timedOut)
            else
                ok = pcall(callback, cx)
            end
            if not ok then onError(cx, ACTION_ERROR) end
        end
    end

    local function enqueue(job)
        prune()
        if not isCurrent(job.token) then
            close(job)
            runner:wake()
            return
        end
        -- Bound both storage and the amount of bookkeeping in a timer hook.
        if #jobs >= MAX_PENDING then error("TURN work queue is full.", 0) end
        table.insert(jobs, job)
        runner:wake()
    end

    function runner:post(token, callback)
        enqueue({ token = token, callback = callback, received = true })
    end

    function runner:wait(token, timeout_ms, callback)
        local job = {
            token = token,
            callback = callback,
            waiting = true,
            received = false,
            deadline = api.now() + math.max(0, timeout_ms),
        }
        enqueue(job)
        return function(result)
            -- No clock, scheduling, parsing, UI, filesystem or native work here.
            -- A receipt wins until timeout delivery closes the job; first receipt wins.
            if not job.closed and not job.received then
                job.result = result
                job.received = true
            end
        end
    end

    return runner
end

return { new = new }
