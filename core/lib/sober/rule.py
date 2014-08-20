# -*- coding: utf-8 -*-
import sober.datasource
import sober.model.ruleobject as ruleobject

class Rule:

    rule = None

    def set_obj(self, obj):
        self.obj = obj

    def get(self, obj=False):
        if obj == False:
            obj = self.obj

        try:
            self.rule = ruleobject.ruleObject(obj).get()
            return self.rule

        except Exception, e:
            print 'rule', str(e)
            return None
