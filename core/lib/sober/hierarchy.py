class Tree:
    def get_tree(self, mail):
        groups = self.get_groups(mail)
        domain =  mail.split('@')[1]
        return (mail,  groups, domain)

    def get_groups(self, mail):
        return (mail)
