#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>
@property (strong) NSWindow *window;
@property (strong) WKWebView *webView;
@property (strong) NSTask *serverTask;
@end

@implementation AppDelegate

- (void)setupMainMenu {
    NSMenu *menubar = [[NSMenu alloc] init];
    NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
    [menubar addItem:appMenuItem];

    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"Sentinel Net"];
    [appMenu addItemWithTitle:@"Quit Sentinel Net" action:@selector(terminate:) keyEquivalent:@"q"];
    [appMenuItem setSubmenu:appMenu];

    NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
    [menubar addItem:editMenuItem];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
    [editMenu addItemWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
    [editMenuItem setSubmenu:editMenu];

    [NSApp setMainMenu:menubar];
}

- (NSString *)startLocalServer {
    NSString *execDir = [[[NSBundle mainBundle] executablePath] stringByDeletingLastPathComponent];
    NSString *serverBin = [execDir stringByAppendingPathComponent:@"sentinel-net"];

    self.serverTask = [[NSTask alloc] init];
    [self.serverTask setExecutableURL:[NSURL fileURLWithPath:serverBin]];
    [self.serverTask setArguments:@[@"serve", @"--host", @"127.0.0.1", @"--port", @"0"]];

    NSPipe *outPipe = [NSPipe pipe];
    [self.serverTask setStandardOutput:outPipe];
    [self.serverTask setStandardError:[NSPipe pipe]];

    NSError *err = nil;
    if (![self.serverTask launchAndReturnError:&err]) {
        return nil;
    }

    NSFileHandle *fh = [outPipe fileHandleForReading];
    NSMutableData *buf = [NSMutableData data];
    for (int i = 0; i < 50; i++) {
        NSData *chunk = [fh availableData];
        if (chunk.length == 0) break;
        [buf appendData:chunk];
        NSString *txt = [[NSString alloc] initWithData:buf encoding:NSUTF8StringEncoding];
        NSRange rng = [txt rangeOfString:@"http://127.0.0.1:"];
        if (rng.location != NSNotFound) {
            NSString *tail = [txt substringFromIndex:rng.location];
            NSArray *lines = [tail componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (lines.count > 0) {
                return lines[0];
            }
        }
    }
    return nil;
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [self setupMainMenu];
    NSString *urlStr = [self startLocalServer];
    if (!urlStr) {
        [NSApp terminate:nil];
        return;
    }

    NSRect frame = NSMakeRect(0, 0, 1360, 860);
    NSUInteger style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                       NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    [self.window setTitle:@"Sentinel Net"];
    [self.window setAppearance:[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua]];
    [self.window center];

    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    self.webView = [[WKWebView alloc] initWithFrame:[[self.window contentView] bounds] configuration:cfg];
    [self.webView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [[self.window contentView] addSubview:self.webView];

    NSURLRequest *req = [NSURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
    [self.webView loadRequest:req];

    [self.window makeKeyAndOrderFront:nil];
    if (@available(macOS 14.0, *)) {
        [NSApp activate];
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [NSApp activateIgnoringOtherApps:YES];
#pragma clang diagnostic pop
    }
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    if (self.serverTask && [self.serverTask isRunning]) {
        [self.serverTask terminate];
        [self.serverTask waitUntilExit];
    }
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        AppDelegate *delegate = [[AppDelegate alloc] init];
        [app setDelegate:delegate];
        [app run];
    }
    return 0;
}
