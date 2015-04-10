//
//  KBPGPOutputFileView.m
//  Keybase
//
//  Created by Gabriel on 3/27/15.
//  Copyright (c) 2015 Gabriel Handford. All rights reserved.
//

#import "KBPGPOutputFileView.h"

#import "KBFileListView.h"
#import "KBPGPOutputFooterView.h"

@interface KBPGPOutputFileView ()
@property KBFileListView *fileListView;
@end

@implementation KBPGPOutputFileView

- (void)viewInit {
  [super viewInit];
  [self kb_setBackgroundColor:KBAppearance.currentAppearance.secondaryBackgroundColor];

  _fileListView = [[KBFileListView alloc] init];
  _fileListView.fileLabelStyle = KBFileLabelStyleLarge;
  _fileListView.onMenuSelect  = ^(NSIndexPath *indexPath) {
    NSMenu *menu = [[NSMenu alloc] initWithTitle:@""];
    [menu addItemWithTitle:@"Show In Finder" action:@selector(showInFinder:) keyEquivalent:@""];
    return menu;
  };
  [self addSubview:_fileListView];

  KBPGPOutputFooterView *footerView = [[KBPGPOutputFooterView alloc] init];
  [self addSubview:footerView];
  footerView.editButton.targetBlock = ^{
    [self.navigation popViewAnimated:YES];
  };
  footerView.closeButton.targetBlock = ^{ [[self window] close]; };

  self.viewLayout = [YOLayout layoutWithLayoutBlock:[KBLayouts borderLayoutWithCenterView:_fileListView topView:nil bottomView:footerView insets:UIEdgeInsetsZero spacing:0 maxSize:CGSizeMake(600, 450)]];
}

- (void)setFiles:(NSArray *)files {
  [_fileListView addObjects:files];
}

- (void)showInFinder:(id)sender {
  KBFile *file = [_fileListView.dataSource objectAtIndexPath:_fileListView.menuIndexPath];
  [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[[NSURL fileURLWithPath:file.path]]];
}

@end
