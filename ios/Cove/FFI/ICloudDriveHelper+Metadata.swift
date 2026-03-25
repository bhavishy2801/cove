import CoveCore
import Foundation

extension ICloudDriveHelper {
    // MARK: - Cloud presence via NSMetadataQuery

    /// Runs an NSMetadataQuery and returns all matching items
    ///
    /// Must NOT be called from the main thread
    func metadataQuery(predicate: NSPredicate) throws -> [NSMetadataItem] {
        let semaphore = DispatchSemaphore(value: 0)
        var results: [NSMetadataItem] = []
        var startFailed = false
        let query = NSMetadataQuery()
        let box = ObserverBox()
        var finalizeWorkItem: DispatchWorkItem?
        var didSignal = false

        let captureResults = {
            (0 ..< query.resultCount).compactMap { query.result(at: $0) as? NSMetadataItem }
        }

        let finishQuery = { (reason: String) in
            guard !didSignal else { return }
            didSignal = true
            finalizeWorkItem?.cancel()
            query.disableUpdates()
            results = captureResults()
            Log.info(
                "metadataQuery: finalized reason=\(reason) count=\(results.count) predicate=\(predicate.predicateFormat)"
            )
            query.stop()
            box.removeAll()
            semaphore.signal()
        }

        DispatchQueue.main.async {
            query.searchScopes = [NSMetadataQueryUbiquitousDataScope]
            query.predicate = predicate

            let scheduleFinalize = { (reason: String) in
                finalizeWorkItem?.cancel()
                let workItem = DispatchWorkItem {
                    finishQuery(reason)
                }
                finalizeWorkItem = workItem
                DispatchQueue.main.asyncAfter(
                    deadline: .now() + self.metadataSettleInterval,
                    execute: workItem
                )
            }

            box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: query,
                    queue: .main
                ) { _ in
                    Log.info(
                        "metadataQuery: finish gathering count=\(query.resultCount) predicate=\(predicate.predicateFormat)"
                    )
                    scheduleFinalize("finish")
                }
            )
            box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidUpdate,
                    object: query,
                    queue: .main
                ) { _ in
                    Log.info(
                        "metadataQuery: update count=\(query.resultCount) predicate=\(predicate.predicateFormat)"
                    )
                    scheduleFinalize("update")
                }
            )

            Log.info("metadataQuery: starting predicate=\(predicate.predicateFormat)")
            if !query.start() {
                startFailed = true
                box.removeAll()
                semaphore.signal()
            }
        }

        if semaphore.wait(timeout: .now() + defaultTimeout) == .timedOut {
            DispatchQueue.main.async {
                finalizeWorkItem?.cancel()
                query.stop()
                box.removeAll()
            }
            throw CloudStorageError.NotAvailable("iCloud metadata query timed out")
        }

        if startFailed {
            throw CloudStorageError.NotAvailable("failed to start iCloud metadata query")
        }

        return results
    }

    /// Authoritatively checks whether a file exists in iCloud (finds evicted files too)
    ///
    /// Must NOT be called from the main thread
    func fileExistsInCloud(name: String) throws -> Bool {
        let predicate = NSPredicate(format: "%K == %@", NSMetadataItemFSNameKey, name)
        let results = try metadataQuery(predicate: predicate)
        return !results.isEmpty
    }

    /// Resolve symlinks so /var and /private/var compare correctly
    private static func resolvedPath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    private static func metadataPath(for item: NSMetadataItem) -> String? {
        if let path = item.value(forAttribute: NSMetadataItemPathKey) as? String {
            return resolvedPath(path)
        }
        if let url = item.value(forAttribute: NSMetadataItemURLKey) as? URL {
            return resolvedPath(url.path)
        }
        return nil
    }

    private static func resolvedItem(
        named name: String,
        under resolvedParent: String,
        in query: NSMetadataQuery
    ) -> ResolvedMetadataItem? {
        let prefix = resolvedParent + "/"

        for index in 0 ..< query.resultCount {
            guard let item = query.result(at: index) as? NSMetadataItem else {
                continue
            }
            guard let itemName = item.value(forAttribute: NSMetadataItemFSNameKey) as? String else {
                continue
            }
            guard itemName == name else { continue }
            guard let metadataURL = item.value(forAttribute: NSMetadataItemURLKey) as? URL else {
                continue
            }
            let metadataPath = Self.metadataPath(for: item)
            if let metadataPath, metadataPath.hasPrefix(prefix) {
                return ResolvedMetadataItem(url: metadataURL, metadataPath: metadataPath)
            }
        }

        return nil
    }

    private static func metadataItemSummary(_ item: NSMetadataItem) -> String {
        let name = (item.value(forAttribute: NSMetadataItemFSNameKey) as? String) ?? "<unknown>"
        let path = metadataPath(for: item) ?? "<no-path>"
        let url =
            ((item.value(forAttribute: NSMetadataItemURLKey) as? URL)?.path) ?? "<no-url>"
        return "name=\(name) path=\(path) url=\(url)"
    }

    private static func metadataItemSummaries(in query: NSMetadataQuery) -> [String] {
        (0 ..< query.resultCount).compactMap { index in
            guard let item = query.result(at: index) as? NSMetadataItem else {
                return nil
            }
            return metadataItemSummary(item)
        }
    }

    func logMetadataItems(
        under parentDirectoryURL: URL,
        reason: String,
        focusName: String
    ) {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let query = NSMetadataQuery()
        let semaphore = DispatchSemaphore(value: 0)
        let box = ObserverBox()
        var didSignal = false

        let finish = {
            guard !didSignal else { return }
            didSignal = true
            let summaries = Self.metadataItemSummaries(in: query)
            Log.info(
                "metadataItems: reason=\(reason) focus=\(focusName) parent=\(resolvedParent) count=\(summaries.count)"
            )
            for summary in summaries {
                Log.info("metadataItems: \(summary)")
            }
            query.stop()
            box.removeAll()
            semaphore.signal()
        }

        DispatchQueue.main.async {
            query.searchScopes = [parentDirectoryURL]
            query.predicate = NSPredicate(value: true)

            box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: query,
                    queue: .main
                ) { _ in
                    finish()
                }
            )
            box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidUpdate,
                    object: query,
                    queue: .main
                ) { _ in
                    finish()
                }
            )

            if !query.start() {
                Log.info(
                    "metadataItems: failed to start reason=\(reason) focus=\(focusName) parent=\(resolvedParent)"
                )
                box.removeAll()
                semaphore.signal()
            }
        }

        if semaphore.wait(timeout: .now() + 5) == .timedOut {
            DispatchQueue.main.async {
                query.stop()
                box.removeAll()
            }
            Log.info(
                "metadataItems: timed out reason=\(reason) focus=\(focusName) parent=\(resolvedParent)"
            )
        }
    }

    func waitForMetadataItem(
        named name: String,
        parentDirectoryURL: URL,
        deadline: Date
    ) throws -> ResolvedMetadataItem {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let predicate = NSPredicate(format: "%K == %@", NSMetadataItemFSNameKey, name)
        let semaphore = DispatchSemaphore(value: 0)
        var resolvedItem: ResolvedMetadataItem?
        var failure: MetadataLookupError?
        let query = NSMetadataQuery()
        let box = ObserverBox()
        var didSignal = false

        let finish = { (item: ResolvedMetadataItem?, error: MetadataLookupError?) in
            guard !didSignal else { return }
            didSignal = true
            resolvedItem = item
            failure = error
            query.stop()
            box.removeAll()
            semaphore.signal()
        }

        DispatchQueue.main.async {
            query.searchScopes = [NSMetadataQueryUbiquitousDataScope]
            query.predicate = predicate

            let evaluate = { (reason: String) in
                if let item = Self.resolvedItem(named: name, under: resolvedParent, in: query) {
                    Log.info(
                        "metadataLookup: resolved name=\(name) reason=\(reason) url=\(item.url.path) metadataPath=\(item.metadataPath ?? "<unknown>")"
                    )
                    finish(item, nil)
                    return
                }

                Log.info(
                    "metadataLookup: no match yet name=\(name) reason=\(reason) count=\(query.resultCount) parent=\(resolvedParent)"
                )
                for summary in Self.metadataItemSummaries(in: query) {
                    Log.info("metadataLookup: item \(summary)")
                }
            }

            box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: query,
                    queue: .main
                ) { _ in
                    evaluate("finish")
                }
            )
            box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidUpdate,
                    object: query,
                    queue: .main
                ) { _ in
                    evaluate("update")
                }
            )

            Log.info(
                "metadataLookup: starting name=\(name) parent=\(resolvedParent) predicate=\(predicate.predicateFormat)"
            )
            if !query.start() {
                finish(
                    nil,
                    .startFailed("failed to start iCloud metadata query for \(name)")
                )
            }
        }

        if semaphore.wait(timeout: .now() + deadline.timeIntervalSinceNow) == .timedOut {
            DispatchQueue.main.async {
                finish(
                    nil,
                    .timedOut("iCloud metadata query timed out for \(name)")
                )
            }
            _ = semaphore.wait(timeout: .now() + 1)
        }

        if let failure {
            throw failure
        }

        guard let resolvedItem else {
            throw MetadataLookupError.missingURL(
                "iCloud metadata query finished without a URL for \(name)"
            )
        }

        return resolvedItem
    }

    func resolvedMetadataItemIfPresent(
        named name: String,
        parentDirectoryURL: URL
    ) -> ResolvedMetadataItem? {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let predicate = NSPredicate(format: "%K == %@", NSMetadataItemFSNameKey, name)
        let semaphore = DispatchSemaphore(value: 0)
        let query = NSMetadataQuery()
        let box = ObserverBox()
        var match: ResolvedMetadataItem?
        var didSignal = false

        let finish = {
            guard !didSignal else { return }
            didSignal = true
            query.stop()
            box.removeAll()
            semaphore.signal()
        }

        DispatchQueue.main.async {
            query.searchScopes = [NSMetadataQueryUbiquitousDataScope]
            query.predicate = predicate

            let evaluate = {
                if let resolved = Self.resolvedItem(named: name, under: resolvedParent, in: query) {
                    match = resolved
                }
                finish()
            }

            box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: query,
                    queue: .main
                ) { _ in
                    evaluate()
                }
            )
            box.add(
                NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidUpdate,
                    object: query,
                    queue: .main
                ) { _ in
                    evaluate()
                }
            )

            if !query.start() {
                finish()
            }
        }

        if semaphore.wait(timeout: .now() + 5) == .timedOut {
            DispatchQueue.main.async {
                finish()
            }
            _ = semaphore.wait(timeout: .now() + 1)
        }

        return match
    }

    func metadataSubdirectoryNames(parentDirectoryURL: URL) throws -> [String] {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let pathPrefix = resolvedParent + "/"
        let items = try metadataQuery(predicate: NSPredicate(value: true))
        var names = Set<String>()

        for item in items {
            guard let metadataPath = Self.metadataPath(for: item) else { continue }
            guard metadataPath.hasPrefix(pathPrefix) else { continue }
            guard let firstComponent = String(metadataPath.dropFirst(pathPrefix.count))
                .split(separator: "/")
                .first
            else {
                continue
            }

            names.insert(String(firstComponent))
        }

        return names.sorted()
    }

    func metadataFileNames(parentDirectoryURL: URL, prefix: String) throws -> [String] {
        let resolvedParent = Self.resolvedPath(parentDirectoryURL.path)
        let pathPrefix = resolvedParent + "/"
        let items = try metadataQuery(predicate: NSPredicate(value: true))
        var names = Set<String>()

        for item in items {
            guard let metadataPath = Self.metadataPath(for: item) else { continue }
            guard metadataPath.hasPrefix(pathPrefix) else { continue }

            let relativePath = String(metadataPath.dropFirst(pathPrefix.count))
            guard !relativePath.contains("/") else { continue }

            let name = URL(fileURLWithPath: relativePath).lastPathComponent
            guard name.hasPrefix(prefix) else { continue }
            names.insert(name)
        }

        return names.sorted()
    }
}
